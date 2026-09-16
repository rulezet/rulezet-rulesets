rule TTP_XOR_WriteProcessMemory_4960 {
  strings:
    $key_4960 = { 1e 12 [2] 2c 30 [2] 2a 05 [2] 04 05 [2] 3b 19 }

  condition:
    any of them
}