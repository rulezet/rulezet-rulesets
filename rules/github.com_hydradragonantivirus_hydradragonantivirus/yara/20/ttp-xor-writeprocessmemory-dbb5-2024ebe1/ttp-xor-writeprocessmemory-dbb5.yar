rule TTP_XOR_WriteProcessMemory_dbb5 {
  strings:
    $key_dbb5 = { 8c c7 [2] be e5 [2] b8 d0 [2] 96 d0 [2] a9 cc }

  condition:
    any of them
}