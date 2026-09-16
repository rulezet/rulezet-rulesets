rule TTP_XOR_WriteProcessMemory_0662 {
  strings:
    $key_0662 = { 51 10 [2] 63 32 [2] 65 07 [2] 4b 07 [2] 74 1b }

  condition:
    any of them
}