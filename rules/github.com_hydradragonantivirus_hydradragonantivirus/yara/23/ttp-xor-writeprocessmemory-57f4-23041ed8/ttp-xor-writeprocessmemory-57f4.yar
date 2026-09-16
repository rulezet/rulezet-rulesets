rule TTP_XOR_WriteProcessMemory_57f4 {
  strings:
    $key_57f4 = { 00 86 [2] 32 a4 [2] 34 91 [2] 1a 91 [2] 25 8d }

  condition:
    any of them
}