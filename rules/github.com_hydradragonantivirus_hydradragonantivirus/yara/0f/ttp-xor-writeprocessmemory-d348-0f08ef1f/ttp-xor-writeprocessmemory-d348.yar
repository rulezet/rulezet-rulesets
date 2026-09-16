rule TTP_XOR_WriteProcessMemory_d348 {
  strings:
    $key_d348 = { 84 3a [2] b6 18 [2] b0 2d [2] 9e 2d [2] a1 31 }

  condition:
    any of them
}