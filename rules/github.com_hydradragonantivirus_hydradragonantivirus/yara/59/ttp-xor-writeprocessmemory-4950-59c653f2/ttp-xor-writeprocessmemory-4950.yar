rule TTP_XOR_WriteProcessMemory_4950 {
  strings:
    $key_4950 = { 1e 22 [2] 2c 00 [2] 2a 35 [2] 04 35 [2] 3b 29 }

  condition:
    any of them
}