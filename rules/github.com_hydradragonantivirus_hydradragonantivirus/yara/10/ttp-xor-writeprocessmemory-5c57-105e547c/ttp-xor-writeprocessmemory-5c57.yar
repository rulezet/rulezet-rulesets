rule TTP_XOR_WriteProcessMemory_5c57 {
  strings:
    $key_5c57 = { 0b 25 [2] 39 07 [2] 3f 32 [2] 11 32 [2] 2e 2e }

  condition:
    any of them
}