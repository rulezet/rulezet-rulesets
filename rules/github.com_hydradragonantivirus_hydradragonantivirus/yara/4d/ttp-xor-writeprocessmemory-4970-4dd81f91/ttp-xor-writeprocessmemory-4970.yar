rule TTP_XOR_WriteProcessMemory_4970 {
  strings:
    $key_4970 = { 1e 02 [2] 2c 20 [2] 2a 15 [2] 04 15 [2] 3b 09 }

  condition:
    any of them
}