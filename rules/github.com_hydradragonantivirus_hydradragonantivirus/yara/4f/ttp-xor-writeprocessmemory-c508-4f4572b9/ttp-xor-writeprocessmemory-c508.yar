rule TTP_XOR_WriteProcessMemory_c508 {
  strings:
    $key_c508 = { 92 7a [2] a0 58 [2] a6 6d [2] 88 6d [2] b7 71 }

  condition:
    any of them
}