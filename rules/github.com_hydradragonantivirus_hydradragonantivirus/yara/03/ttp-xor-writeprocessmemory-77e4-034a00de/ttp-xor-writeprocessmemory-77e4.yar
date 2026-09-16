rule TTP_XOR_WriteProcessMemory_77e4 {
  strings:
    $key_77e4 = { 20 96 [2] 12 b4 [2] 14 81 [2] 3a 81 [2] 05 9d }

  condition:
    any of them
}