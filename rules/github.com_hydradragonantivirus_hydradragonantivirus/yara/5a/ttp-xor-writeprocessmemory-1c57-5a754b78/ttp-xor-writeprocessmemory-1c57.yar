rule TTP_XOR_WriteProcessMemory_1c57 {
  strings:
    $key_1c57 = { 4b 25 [2] 79 07 [2] 7f 32 [2] 51 32 [2] 6e 2e }

  condition:
    any of them
}