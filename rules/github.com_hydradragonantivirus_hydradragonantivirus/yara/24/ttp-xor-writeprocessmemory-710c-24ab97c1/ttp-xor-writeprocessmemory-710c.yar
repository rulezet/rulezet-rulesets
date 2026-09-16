rule TTP_XOR_WriteProcessMemory_710c {
  strings:
    $key_710c = { 26 7e [2] 14 5c [2] 12 69 [2] 3c 69 [2] 03 75 }

  condition:
    any of them
}