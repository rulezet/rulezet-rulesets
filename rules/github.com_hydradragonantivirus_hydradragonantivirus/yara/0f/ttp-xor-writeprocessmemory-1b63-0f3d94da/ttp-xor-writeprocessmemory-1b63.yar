rule TTP_XOR_WriteProcessMemory_1b63 {
  strings:
    $key_1b63 = { 4c 11 [2] 7e 33 [2] 78 06 [2] 56 06 [2] 69 1a }

  condition:
    any of them
}