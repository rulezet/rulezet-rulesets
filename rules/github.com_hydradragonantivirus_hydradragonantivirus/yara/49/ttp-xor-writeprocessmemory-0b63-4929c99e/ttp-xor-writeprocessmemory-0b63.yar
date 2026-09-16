rule TTP_XOR_WriteProcessMemory_0b63 {
  strings:
    $key_0b63 = { 5c 11 [2] 6e 33 [2] 68 06 [2] 46 06 [2] 79 1a }

  condition:
    any of them
}