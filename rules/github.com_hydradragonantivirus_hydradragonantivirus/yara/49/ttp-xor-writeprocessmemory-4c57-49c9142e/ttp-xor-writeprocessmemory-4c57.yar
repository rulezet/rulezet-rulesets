rule TTP_XOR_WriteProcessMemory_4c57 {
  strings:
    $key_4c57 = { 1b 25 [2] 29 07 [2] 2f 32 [2] 01 32 [2] 3e 2e }

  condition:
    any of them
}