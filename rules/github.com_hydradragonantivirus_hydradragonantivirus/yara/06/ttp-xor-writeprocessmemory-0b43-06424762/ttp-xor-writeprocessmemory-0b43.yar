rule TTP_XOR_WriteProcessMemory_0b43 {
  strings:
    $key_0b43 = { 5c 31 [2] 6e 13 [2] 68 26 [2] 46 26 [2] 79 3a }

  condition:
    any of them
}