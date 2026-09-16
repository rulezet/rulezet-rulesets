rule TTP_XOR_WriteProcessMemory_4b63 {
  strings:
    $key_4b63 = { 1c 11 [2] 2e 33 [2] 28 06 [2] 06 06 [2] 39 1a }

  condition:
    any of them
}