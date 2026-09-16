rule TTP_XOR_WriteProcessMemory_3b63 {
  strings:
    $key_3b63 = { 6c 11 [2] 5e 33 [2] 58 06 [2] 76 06 [2] 49 1a }

  condition:
    any of them
}