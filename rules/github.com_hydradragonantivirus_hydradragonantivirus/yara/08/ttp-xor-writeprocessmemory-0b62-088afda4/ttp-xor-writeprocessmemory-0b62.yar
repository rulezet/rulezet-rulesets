rule TTP_XOR_WriteProcessMemory_0b62 {
  strings:
    $key_0b62 = { 5c 10 [2] 6e 32 [2] 68 07 [2] 46 07 [2] 79 1b }

  condition:
    any of them
}