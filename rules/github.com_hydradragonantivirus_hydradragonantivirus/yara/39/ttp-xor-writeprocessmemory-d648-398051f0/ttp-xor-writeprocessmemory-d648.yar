rule TTP_XOR_WriteProcessMemory_d648 {
  strings:
    $key_d648 = { 81 3a [2] b3 18 [2] b5 2d [2] 9b 2d [2] a4 31 }

  condition:
    any of them
}