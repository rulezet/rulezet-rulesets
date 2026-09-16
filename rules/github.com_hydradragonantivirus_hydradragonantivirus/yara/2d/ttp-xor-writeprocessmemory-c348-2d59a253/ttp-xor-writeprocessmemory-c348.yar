rule TTP_XOR_WriteProcessMemory_c348 {
  strings:
    $key_c348 = { 94 3a [2] a6 18 [2] a0 2d [2] 8e 2d [2] b1 31 }

  condition:
    any of them
}