rule TTP_XOR_WriteProcessMemory_4e84 {
  strings:
    $key_4e84 = { 19 f6 [2] 2b d4 [2] 2d e1 [2] 03 e1 [2] 3c fd }

  condition:
    any of them
}