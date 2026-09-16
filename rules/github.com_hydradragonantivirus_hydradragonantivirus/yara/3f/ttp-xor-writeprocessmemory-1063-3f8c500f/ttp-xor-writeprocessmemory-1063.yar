rule TTP_XOR_WriteProcessMemory_1063 {
  strings:
    $key_1063 = { 47 11 [2] 75 33 [2] 73 06 [2] 5d 06 [2] 62 1a }

  condition:
    any of them
}