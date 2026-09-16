rule TTP_XOR_WriteProcessMemory_6315 {
  strings:
    $key_6315 = { 34 67 [2] 06 45 [2] 00 70 [2] 2e 70 [2] 11 6c }

  condition:
    any of them
}