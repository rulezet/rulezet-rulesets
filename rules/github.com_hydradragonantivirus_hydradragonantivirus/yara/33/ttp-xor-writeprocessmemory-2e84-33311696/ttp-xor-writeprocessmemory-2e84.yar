rule TTP_XOR_WriteProcessMemory_2e84 {
  strings:
    $key_2e84 = { 79 f6 [2] 4b d4 [2] 4d e1 [2] 63 e1 [2] 5c fd }

  condition:
    any of them
}