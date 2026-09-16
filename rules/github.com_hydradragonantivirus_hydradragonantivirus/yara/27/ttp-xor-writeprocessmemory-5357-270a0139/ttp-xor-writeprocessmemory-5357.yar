rule TTP_XOR_WriteProcessMemory_5357 {
  strings:
    $key_5357 = { 04 25 [2] 36 07 [2] 30 32 [2] 1e 32 [2] 21 2e }

  condition:
    any of them
}