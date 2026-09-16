rule TTP_XOR_WriteProcessMemory_6957 {
  strings:
    $key_6957 = { 3e 25 [2] 0c 07 [2] 0a 32 [2] 24 32 [2] 1b 2e }

  condition:
    any of them
}