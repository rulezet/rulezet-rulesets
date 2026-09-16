rule TTP_XOR_WriteProcessMemory_7f57 {
  strings:
    $key_7f57 = { 28 25 [2] 1a 07 [2] 1c 32 [2] 32 32 [2] 0d 2e }

  condition:
    any of them
}