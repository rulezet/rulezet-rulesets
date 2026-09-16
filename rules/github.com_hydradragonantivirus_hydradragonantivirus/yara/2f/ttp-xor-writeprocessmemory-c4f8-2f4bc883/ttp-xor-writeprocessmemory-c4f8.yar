rule TTP_XOR_WriteProcessMemory_c4f8 {
  strings:
    $key_c4f8 = { 93 8a [2] a1 a8 [2] a7 9d [2] 89 9d [2] b6 81 }

  condition:
    any of them
}