rule TTP_XOR_WriteProcessMemory_67e4 {
  strings:
    $key_67e4 = { 30 96 [2] 02 b4 [2] 04 81 [2] 2a 81 [2] 15 9d }

  condition:
    any of them
}