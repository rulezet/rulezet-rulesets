rule TTP_XOR_WriteProcessMemory_1522 {
  strings:
    $key_1522 = { 42 50 [2] 70 72 [2] 76 47 [2] 58 47 [2] 67 5b }

  condition:
    any of them
}