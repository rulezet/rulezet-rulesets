rule TTP_XOR_WriteProcessMemory_4932 {
  strings:
    $key_4932 = { 1e 40 [2] 2c 62 [2] 2a 57 [2] 04 57 [2] 3b 4b }

  condition:
    any of them
}