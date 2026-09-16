rule TTP_XOR_WriteProcessMemory_3e84 {
  strings:
    $key_3e84 = { 69 f6 [2] 5b d4 [2] 5d e1 [2] 73 e1 [2] 4c fd }

  condition:
    any of them
}