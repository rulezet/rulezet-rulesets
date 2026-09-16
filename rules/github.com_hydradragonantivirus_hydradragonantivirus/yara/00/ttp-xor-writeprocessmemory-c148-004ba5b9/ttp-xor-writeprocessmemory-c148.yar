rule TTP_XOR_WriteProcessMemory_c148 {
  strings:
    $key_c148 = { 96 3a [2] a4 18 [2] a2 2d [2] 8c 2d [2] b3 31 }

  condition:
    any of them
}