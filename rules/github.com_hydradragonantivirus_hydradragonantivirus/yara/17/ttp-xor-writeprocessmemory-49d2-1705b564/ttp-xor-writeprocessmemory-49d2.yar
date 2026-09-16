rule TTP_XOR_WriteProcessMemory_49d2 {
  strings:
    $key_49d2 = { 1e a0 [2] 2c 82 [2] 2a b7 [2] 04 b7 [2] 3b ab }

  condition:
    any of them
}