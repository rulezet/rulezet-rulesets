rule TTP_XOR_WriteProcessMemory_6c57 {
  strings:
    $key_6c57 = { 3b 25 [2] 09 07 [2] 0f 32 [2] 21 32 [2] 1e 2e }

  condition:
    any of them
}