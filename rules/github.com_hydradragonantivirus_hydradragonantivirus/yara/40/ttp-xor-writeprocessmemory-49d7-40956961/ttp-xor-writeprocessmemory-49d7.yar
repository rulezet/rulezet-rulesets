rule TTP_XOR_WriteProcessMemory_49d7 {
  strings:
    $key_49d7 = { 1e a5 [2] 2c 87 [2] 2a b2 [2] 04 b2 [2] 3b ae }

  condition:
    any of them
}