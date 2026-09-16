rule TTP_XOR_WriteProcessMemory_4900 {
  strings:
    $key_4900 = { 1e 72 [2] 2c 50 [2] 2a 65 [2] 04 65 [2] 3b 79 }

  condition:
    any of them
}