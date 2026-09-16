rule TTP_XOR_WriteProcessMemory_1e84 {
  strings:
    $key_1e84 = { 49 f6 [2] 7b d4 [2] 7d e1 [2] 53 e1 [2] 6c fd }

  condition:
    any of them
}