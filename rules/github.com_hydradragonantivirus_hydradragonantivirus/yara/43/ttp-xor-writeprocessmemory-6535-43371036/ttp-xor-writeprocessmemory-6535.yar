rule TTP_XOR_WriteProcessMemory_6535 {
  strings:
    $key_6535 = { 32 47 [2] 00 65 [2] 06 50 [2] 28 50 [2] 17 4c }

  condition:
    any of them
}