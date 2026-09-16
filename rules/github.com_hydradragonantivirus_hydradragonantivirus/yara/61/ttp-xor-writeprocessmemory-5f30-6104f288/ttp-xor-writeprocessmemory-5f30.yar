rule TTP_XOR_WriteProcessMemory_5f30 {
  strings:
    $key_5f30 = { 08 42 [2] 3a 60 [2] 3c 55 [2] 12 55 [2] 2d 49 }

  condition:
    any of them
}