rule TTP_XOR_WriteProcessMemory_67e6 {
  strings:
    $key_67e6 = { 30 94 [2] 02 b6 [2] 04 83 [2] 2a 83 [2] 15 9f }

  condition:
    any of them
}