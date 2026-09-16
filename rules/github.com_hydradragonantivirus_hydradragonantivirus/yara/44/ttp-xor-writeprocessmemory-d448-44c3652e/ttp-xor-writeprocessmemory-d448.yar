rule TTP_XOR_WriteProcessMemory_d448 {
  strings:
    $key_d448 = { 83 3a [2] b1 18 [2] b7 2d [2] 99 2d [2] a6 31 }

  condition:
    any of them
}