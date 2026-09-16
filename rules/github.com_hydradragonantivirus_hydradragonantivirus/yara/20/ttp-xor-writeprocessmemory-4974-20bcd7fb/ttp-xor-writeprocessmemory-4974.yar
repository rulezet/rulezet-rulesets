rule TTP_XOR_WriteProcessMemory_4974 {
  strings:
    $key_4974 = { 1e 06 [2] 2c 24 [2] 2a 11 [2] 04 11 [2] 3b 0d }

  condition:
    any of them
}