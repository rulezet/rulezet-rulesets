rule TTP_XOR_WriteProcessMemory_7263 {
  strings:
    $key_7263 = { 25 11 [2] 17 33 [2] 11 06 [2] 3f 06 [2] 00 1a }

  condition:
    any of them
}