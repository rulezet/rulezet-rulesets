rule TTP_XOR_WriteProcessMemory_7515 {
  strings:
    $key_7515 = { 22 67 [2] 10 45 [2] 16 70 [2] 38 70 [2] 07 6c }

  condition:
    any of them
}