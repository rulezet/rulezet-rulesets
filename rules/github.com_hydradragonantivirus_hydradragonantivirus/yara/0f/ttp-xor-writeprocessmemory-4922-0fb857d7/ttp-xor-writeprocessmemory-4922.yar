rule TTP_XOR_WriteProcessMemory_4922 {
  strings:
    $key_4922 = { 1e 50 [2] 2c 72 [2] 2a 47 [2] 04 47 [2] 3b 5b }

  condition:
    any of them
}