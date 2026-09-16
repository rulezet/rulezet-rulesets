rule TTP_XOR_WriteProcessMemory_1d62 {
  strings:
    $key_1d62 = { 4a 10 [2] 78 32 [2] 7e 07 [2] 50 07 [2] 6f 1b }

  condition:
    any of them
}