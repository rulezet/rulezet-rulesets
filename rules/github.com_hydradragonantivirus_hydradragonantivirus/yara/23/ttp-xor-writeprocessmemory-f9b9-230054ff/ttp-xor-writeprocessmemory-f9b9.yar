rule TTP_XOR_WriteProcessMemory_f9b9 {
  strings:
    $key_f9b9 = { ae cb [2] 9c e9 [2] 9a dc [2] b4 dc [2] 8b c0 }

  condition:
    any of them
}