rule TTP_XOR_WriteProcessMemory_1d57 {
  strings:
    $key_1d57 = { 4a 25 [2] 78 07 [2] 7e 32 [2] 50 32 [2] 6f 2e }

  condition:
    any of them
}