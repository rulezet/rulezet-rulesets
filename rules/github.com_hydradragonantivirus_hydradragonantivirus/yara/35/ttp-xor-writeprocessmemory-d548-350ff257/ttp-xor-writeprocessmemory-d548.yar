rule TTP_XOR_WriteProcessMemory_d548 {
  strings:
    $key_d548 = { 82 3a [2] b0 18 [2] b6 2d [2] 98 2d [2] a7 31 }

  condition:
    any of them
}