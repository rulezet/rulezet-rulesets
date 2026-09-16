rule TTP_XOR_WriteProcessMemory_73e6 {
  strings:
    $key_73e6 = { 24 94 [2] 16 b6 [2] 10 83 [2] 3e 83 [2] 01 9f }

  condition:
    any of them
}