rule TTP_XOR_WriteProcessMemory_7357 {
  strings:
    $key_7357 = { 24 25 [2] 16 07 [2] 10 32 [2] 3e 32 [2] 01 2e }

  condition:
    any of them
}