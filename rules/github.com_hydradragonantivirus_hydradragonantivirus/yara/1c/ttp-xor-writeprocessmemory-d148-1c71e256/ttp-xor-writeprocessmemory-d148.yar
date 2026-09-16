rule TTP_XOR_WriteProcessMemory_d148 {
  strings:
    $key_d148 = { 86 3a [2] b4 18 [2] b2 2d [2] 9c 2d [2] a3 31 }

  condition:
    any of them
}