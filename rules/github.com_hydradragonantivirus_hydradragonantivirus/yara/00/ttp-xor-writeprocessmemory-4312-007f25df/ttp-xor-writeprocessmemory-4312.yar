rule TTP_XOR_WriteProcessMemory_4312 {
  strings:
    $key_4312 = { 14 60 [2] 26 42 [2] 20 77 [2] 0e 77 [2] 31 6b }

  condition:
    any of them
}