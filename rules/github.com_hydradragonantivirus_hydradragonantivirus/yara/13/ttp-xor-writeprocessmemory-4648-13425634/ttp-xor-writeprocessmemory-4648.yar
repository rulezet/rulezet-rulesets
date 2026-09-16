rule TTP_XOR_WriteProcessMemory_4648 {
  strings:
    $key_4648 = { 11 3a [2] 23 18 [2] 25 2d [2] 0b 2d [2] 34 31 }

  condition:
    any of them
}