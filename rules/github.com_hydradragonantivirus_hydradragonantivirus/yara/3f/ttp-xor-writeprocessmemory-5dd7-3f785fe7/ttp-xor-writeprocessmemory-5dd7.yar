rule TTP_XOR_WriteProcessMemory_5dd7 {
  strings:
    $key_5dd7 = { 0a a5 [2] 38 87 [2] 3e b2 [2] 10 b2 [2] 2f ae }

  condition:
    any of them
}