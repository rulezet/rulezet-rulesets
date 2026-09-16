rule TTP_XOR_WriteProcessMemory_2f48 {
  strings:
    $key_2f48 = { 78 3a [2] 4a 18 [2] 4c 2d [2] 62 2d [2] 5d 31 }

  condition:
    any of them
}