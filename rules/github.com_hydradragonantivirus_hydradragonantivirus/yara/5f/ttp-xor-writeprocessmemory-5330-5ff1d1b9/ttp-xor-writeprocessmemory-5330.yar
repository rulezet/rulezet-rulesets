rule TTP_XOR_WriteProcessMemory_5330 {
  strings:
    $key_5330 = { 04 42 [2] 36 60 [2] 30 55 [2] 1e 55 [2] 21 49 }

  condition:
    any of them
}