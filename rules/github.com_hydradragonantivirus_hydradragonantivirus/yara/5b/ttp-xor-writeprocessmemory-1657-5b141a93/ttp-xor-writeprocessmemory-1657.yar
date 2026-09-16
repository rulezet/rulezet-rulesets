rule TTP_XOR_WriteProcessMemory_1657 {
  strings:
    $key_1657 = { 41 25 [2] 73 07 [2] 75 32 [2] 5b 32 [2] 64 2e }

  condition:
    any of them
}