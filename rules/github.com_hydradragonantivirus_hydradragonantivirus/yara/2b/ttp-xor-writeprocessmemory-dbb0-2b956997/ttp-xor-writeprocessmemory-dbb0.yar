rule TTP_XOR_WriteProcessMemory_dbb0 {
  strings:
    $key_dbb0 = { 8c c2 [2] be e0 [2] b8 d5 [2] 96 d5 [2] a9 c9 }

  condition:
    any of them
}