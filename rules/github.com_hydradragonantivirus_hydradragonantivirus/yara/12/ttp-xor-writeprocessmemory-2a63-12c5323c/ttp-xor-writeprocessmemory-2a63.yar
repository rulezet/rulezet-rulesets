rule TTP_XOR_WriteProcessMemory_2a63 {
  strings:
    $key_2a63 = { 7d 11 [2] 4f 33 [2] 49 06 [2] 67 06 [2] 58 1a }

  condition:
    any of them
}