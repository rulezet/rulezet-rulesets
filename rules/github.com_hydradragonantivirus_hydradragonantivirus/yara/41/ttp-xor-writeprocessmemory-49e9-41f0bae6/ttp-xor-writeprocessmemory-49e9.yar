rule TTP_XOR_WriteProcessMemory_49e9 {
  strings:
    $key_49e9 = { 1e 9b [2] 2c b9 [2] 2a 8c [2] 04 8c [2] 3b 90 }

  condition:
    any of them
}