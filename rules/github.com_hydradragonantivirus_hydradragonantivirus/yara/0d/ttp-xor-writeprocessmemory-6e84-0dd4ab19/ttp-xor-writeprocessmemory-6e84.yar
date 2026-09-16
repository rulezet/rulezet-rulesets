rule TTP_XOR_WriteProcessMemory_6e84 {
  strings:
    $key_6e84 = { 39 f6 [2] 0b d4 [2] 0d e1 [2] 23 e1 [2] 1c fd }

  condition:
    any of them
}