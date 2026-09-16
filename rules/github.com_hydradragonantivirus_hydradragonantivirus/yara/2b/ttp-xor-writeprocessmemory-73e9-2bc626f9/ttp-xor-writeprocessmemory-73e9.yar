rule TTP_XOR_WriteProcessMemory_73e9 {
  strings:
    $key_73e9 = { 24 9b [2] 16 b9 [2] 10 8c [2] 3e 8c [2] 01 90 }

  condition:
    any of them
}