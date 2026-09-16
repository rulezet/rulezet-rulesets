rule TTP_XOR_WriteProcessMemory_49e4 {
  strings:
    $key_49e4 = { 1e 96 [2] 2c b4 [2] 2a 81 [2] 04 81 [2] 3b 9d }

  condition:
    any of them
}