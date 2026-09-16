rule TTP_XOR_WriteProcessMemory_4764 {
  strings:
    $key_4764 = { 10 16 [2] 22 34 [2] 24 01 [2] 0a 01 [2] 35 1d }

  condition:
    any of them
}