rule TTP_XOR_WriteProcessMemory_37e4 {
  strings:
    $key_37e4 = { 60 96 [2] 52 b4 [2] 54 81 [2] 7a 81 [2] 45 9d }

  condition:
    any of them
}