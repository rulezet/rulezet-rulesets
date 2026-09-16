rule TTP_XOR_WriteProcessMemory_1e57 {
  strings:
    $key_1e57 = { 49 25 [2] 7b 07 [2] 7d 32 [2] 53 32 [2] 6c 2e }

  condition:
    any of them
}