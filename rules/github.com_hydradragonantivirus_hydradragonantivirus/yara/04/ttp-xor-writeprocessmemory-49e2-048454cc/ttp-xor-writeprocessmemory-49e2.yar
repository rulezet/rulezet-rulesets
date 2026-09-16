rule TTP_XOR_WriteProcessMemory_49e2 {
  strings:
    $key_49e2 = { 1e 90 [2] 2c b2 [2] 2a 87 [2] 04 87 [2] 3b 9b }

  condition:
    any of them
}