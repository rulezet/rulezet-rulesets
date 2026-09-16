rule TTP_XOR_WriteProcessMemory_3a97 {
  strings:
    $key_3a97 = { 6d e5 [2] 5f c7 [2] 59 f2 [2] 77 f2 [2] 48 ee }

  condition:
    any of them
}