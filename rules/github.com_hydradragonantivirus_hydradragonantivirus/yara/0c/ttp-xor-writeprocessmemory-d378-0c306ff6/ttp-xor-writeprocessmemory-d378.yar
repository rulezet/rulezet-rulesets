rule TTP_XOR_WriteProcessMemory_d378 {
  strings:
    $key_d378 = { 84 0a [2] b6 28 [2] b0 1d [2] 9e 1d [2] a1 01 }

  condition:
    any of them
}