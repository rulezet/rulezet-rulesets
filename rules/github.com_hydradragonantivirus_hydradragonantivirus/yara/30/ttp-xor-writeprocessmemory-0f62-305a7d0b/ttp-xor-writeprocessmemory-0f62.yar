rule TTP_XOR_WriteProcessMemory_0f62 {
  strings:
    $key_0f62 = { 58 10 [2] 6a 32 [2] 6c 07 [2] 42 07 [2] 7d 1b }

  condition:
    any of them
}