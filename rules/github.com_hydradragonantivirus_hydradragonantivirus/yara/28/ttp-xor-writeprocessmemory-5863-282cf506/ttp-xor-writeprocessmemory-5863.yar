rule TTP_XOR_WriteProcessMemory_5863 {
  strings:
    $key_5863 = { 0f 11 [2] 3d 33 [2] 3b 06 [2] 15 06 [2] 2a 1a }

  condition:
    any of them
}