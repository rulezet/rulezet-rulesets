rule TTP_XOR_WriteProcessMemory_5f0c {
  strings:
    $key_5f0c = { 08 7e [2] 3a 5c [2] 3c 69 [2] 12 69 [2] 2d 75 }

  condition:
    any of them
}