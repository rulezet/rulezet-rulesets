rule TTP_XOR_WriteProcessMemory_1662 {
  strings:
    $key_1662 = { 41 10 [2] 73 32 [2] 75 07 [2] 5b 07 [2] 64 1b }

  condition:
    any of them
}