rule TTP_XOR_WriteProcessMemory_4962 {
  strings:
    $key_4962 = { 1e 10 [2] 2c 32 [2] 2a 07 [2] 04 07 [2] 3b 1b }

  condition:
    any of them
}