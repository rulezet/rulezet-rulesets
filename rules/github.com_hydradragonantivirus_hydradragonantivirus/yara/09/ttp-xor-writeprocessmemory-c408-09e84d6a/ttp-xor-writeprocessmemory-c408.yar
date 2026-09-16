rule TTP_XOR_WriteProcessMemory_c408 {
  strings:
    $key_c408 = { 93 7a [2] a1 58 [2] a7 6d [2] 89 6d [2] b6 71 }

  condition:
    any of them
}