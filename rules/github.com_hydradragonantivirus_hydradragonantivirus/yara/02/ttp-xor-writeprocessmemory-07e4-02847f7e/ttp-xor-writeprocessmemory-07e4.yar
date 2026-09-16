rule TTP_XOR_WriteProcessMemory_07e4 {
  strings:
    $key_07e4 = { 50 96 [2] 62 b4 [2] 64 81 [2] 4a 81 [2] 75 9d }

  condition:
    any of them
}