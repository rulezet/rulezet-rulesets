rule TTP_XOR_WriteProcessMemory_4972 {
  strings:
    $key_4972 = { 1e 00 [2] 2c 22 [2] 2a 17 [2] 04 17 [2] 3b 0b }

  condition:
    any of them
}