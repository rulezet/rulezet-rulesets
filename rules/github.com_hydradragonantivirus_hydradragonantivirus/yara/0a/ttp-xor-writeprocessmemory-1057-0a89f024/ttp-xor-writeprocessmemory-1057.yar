rule TTP_XOR_WriteProcessMemory_1057 {
  strings:
    $key_1057 = { 47 25 [2] 75 07 [2] 73 32 [2] 5d 32 [2] 62 2e }

  condition:
    any of them
}