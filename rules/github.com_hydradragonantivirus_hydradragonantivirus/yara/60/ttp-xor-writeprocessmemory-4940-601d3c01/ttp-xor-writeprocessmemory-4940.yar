rule TTP_XOR_WriteProcessMemory_4940 {
  strings:
    $key_4940 = { 1e 32 [2] 2c 10 [2] 2a 25 [2] 04 25 [2] 3b 39 }

  condition:
    any of them
}