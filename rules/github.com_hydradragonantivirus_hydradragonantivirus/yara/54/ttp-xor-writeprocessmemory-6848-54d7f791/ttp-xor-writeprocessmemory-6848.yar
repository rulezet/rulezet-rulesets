rule TTP_XOR_WriteProcessMemory_6848 {
  strings:
    $key_6848 = { 3f 3a [2] 0d 18 [2] 0b 2d [2] 25 2d [2] 1a 31 }

  condition:
    any of them
}