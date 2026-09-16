rule TTP_XOR_WriteProcessMemory_cbb5 {
  strings:
    $key_cbb5 = { 9c c7 [2] ae e5 [2] a8 d0 [2] 86 d0 [2] b9 cc }

  condition:
    any of them
}