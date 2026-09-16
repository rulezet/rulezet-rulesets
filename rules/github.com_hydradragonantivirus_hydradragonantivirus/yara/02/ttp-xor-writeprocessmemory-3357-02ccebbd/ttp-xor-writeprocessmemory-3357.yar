rule TTP_XOR_WriteProcessMemory_3357 {
  strings:
    $key_3357 = { 64 25 [2] 56 07 [2] 50 32 [2] 7e 32 [2] 41 2e }

  condition:
    any of them
}