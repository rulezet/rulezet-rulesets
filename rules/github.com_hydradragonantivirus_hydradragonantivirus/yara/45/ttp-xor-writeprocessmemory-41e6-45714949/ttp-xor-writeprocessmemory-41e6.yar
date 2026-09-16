rule TTP_XOR_WriteProcessMemory_41e6 {
  strings:
    $key_41e6 = { 16 94 [2] 24 b6 [2] 22 83 [2] 0c 83 [2] 33 9f }

  condition:
    any of them
}