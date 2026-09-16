rule TTP_XOR_WriteProcessMemory_5b63 {
  strings:
    $key_5b63 = { 0c 11 [2] 3e 33 [2] 38 06 [2] 16 06 [2] 29 1a }

  condition:
    any of them
}