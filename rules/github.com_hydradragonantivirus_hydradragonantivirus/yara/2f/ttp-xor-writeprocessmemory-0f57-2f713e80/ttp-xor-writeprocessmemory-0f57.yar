rule TTP_XOR_WriteProcessMemory_0f57 {
  strings:
    $key_0f57 = { 58 25 [2] 6a 07 [2] 6c 32 [2] 42 32 [2] 7d 2e }

  condition:
    any of them
}