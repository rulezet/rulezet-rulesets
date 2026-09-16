rule TTP_XOR_WriteProcessMemory_c2f8 {
  strings:
    $key_c2f8 = { 95 8a [2] a7 a8 [2] a1 9d [2] 8f 9d [2] b0 81 }

  condition:
    any of them
}