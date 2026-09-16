rule TTP_XOR_WriteProcessMemory_2c57 {
  strings:
    $key_2c57 = { 7b 25 [2] 49 07 [2] 4f 32 [2] 61 32 [2] 5e 2e }

  condition:
    any of them
}