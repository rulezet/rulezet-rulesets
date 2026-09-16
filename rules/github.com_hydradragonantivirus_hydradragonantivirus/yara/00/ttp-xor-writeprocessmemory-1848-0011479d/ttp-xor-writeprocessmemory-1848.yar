rule TTP_XOR_WriteProcessMemory_1848 {
  strings:
    $key_1848 = { 4f 3a [2] 7d 18 [2] 7b 2d [2] 55 2d [2] 6a 31 }

  condition:
    any of them
}