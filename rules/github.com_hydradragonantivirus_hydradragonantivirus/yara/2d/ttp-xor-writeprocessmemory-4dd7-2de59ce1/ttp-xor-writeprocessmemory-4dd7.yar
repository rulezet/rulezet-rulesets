rule TTP_XOR_WriteProcessMemory_4dd7 {
  strings:
    $key_4dd7 = { 1a a5 [2] 28 87 [2] 2e b2 [2] 00 b2 [2] 3f ae }

  condition:
    any of them
}