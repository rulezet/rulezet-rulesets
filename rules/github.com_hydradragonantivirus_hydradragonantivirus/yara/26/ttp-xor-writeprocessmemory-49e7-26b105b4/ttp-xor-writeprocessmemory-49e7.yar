rule TTP_XOR_WriteProcessMemory_49e7 {
  strings:
    $key_49e7 = { 1e 95 [2] 2c b7 [2] 2a 82 [2] 04 82 [2] 3b 9e }

  condition:
    any of them
}