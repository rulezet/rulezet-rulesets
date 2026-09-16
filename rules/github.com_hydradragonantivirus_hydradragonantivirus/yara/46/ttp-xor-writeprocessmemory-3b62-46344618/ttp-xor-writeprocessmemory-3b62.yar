rule TTP_XOR_WriteProcessMemory_3b62 {
  strings:
    $key_3b62 = { 6c 10 [2] 5e 32 [2] 58 07 [2] 76 07 [2] 49 1b }

  condition:
    any of them
}