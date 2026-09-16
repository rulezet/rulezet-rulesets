rule TTP_XOR_WriteProcessMemory_53e4 {
  strings:
    $key_53e4 = { 04 96 [2] 36 b4 [2] 30 81 [2] 1e 81 [2] 21 9d }

  condition:
    any of them
}