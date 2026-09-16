rule TTP_XOR_WriteProcessMemory_4315 {
  strings:
    $key_4315 = { 14 67 [2] 26 45 [2] 20 70 [2] 0e 70 [2] 31 6c }

  condition:
    any of them
}