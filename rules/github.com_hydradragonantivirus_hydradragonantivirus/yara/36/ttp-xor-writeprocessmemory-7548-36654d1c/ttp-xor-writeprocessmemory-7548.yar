rule TTP_XOR_WriteProcessMemory_7548 {
  strings:
    $key_7548 = { 22 3a [2] 10 18 [2] 16 2d [2] 38 2d [2] 07 31 }

  condition:
    any of them
}