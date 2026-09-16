rule TTP_XOR_WriteProcessMemory_2f41 {
  strings:
    $key_2f41 = { 78 33 [2] 4a 11 [2] 4c 24 [2] 62 24 [2] 5d 38 }

  condition:
    any of them
}