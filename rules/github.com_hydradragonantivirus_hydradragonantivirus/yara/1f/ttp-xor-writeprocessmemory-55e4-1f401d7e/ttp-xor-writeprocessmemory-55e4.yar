rule TTP_XOR_WriteProcessMemory_55e4 {
  strings:
    $key_55e4 = { 02 96 [2] 30 b4 [2] 36 81 [2] 18 81 [2] 27 9d }

  condition:
    any of them
}