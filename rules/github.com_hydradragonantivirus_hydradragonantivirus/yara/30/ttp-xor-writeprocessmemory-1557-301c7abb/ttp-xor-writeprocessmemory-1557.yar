rule TTP_XOR_WriteProcessMemory_1557 {
  strings:
    $key_1557 = { 42 25 [2] 70 07 [2] 76 32 [2] 58 32 [2] 67 2e }

  condition:
    any of them
}