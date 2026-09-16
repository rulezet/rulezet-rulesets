rule TTP_XOR_WriteProcessMemory_7b62 {
  strings:
    $key_7b62 = { 2c 10 [2] 1e 32 [2] 18 07 [2] 36 07 [2] 09 1b }

  condition:
    any of them
}