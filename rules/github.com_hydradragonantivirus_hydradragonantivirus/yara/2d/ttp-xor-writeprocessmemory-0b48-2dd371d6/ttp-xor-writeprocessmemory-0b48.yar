rule TTP_XOR_WriteProcessMemory_0b48 {
  strings:
    $key_0b48 = { 5c 3a [2] 6e 18 [2] 68 2d [2] 46 2d [2] 79 31 }

  condition:
    any of them
}