rule TTP_XOR_WriteProcessMemory_0573 {
  strings:
    $key_0573 = { 52 01 [2] 60 23 [2] 66 16 [2] 48 16 [2] 77 0a }

  condition:
    any of them
}