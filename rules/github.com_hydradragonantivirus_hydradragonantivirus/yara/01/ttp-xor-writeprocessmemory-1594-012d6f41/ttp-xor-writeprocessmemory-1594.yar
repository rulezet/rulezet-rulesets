rule TTP_XOR_WriteProcessMemory_1594 {
  strings:
    $key_1594 = { 42 e6 [2] 70 c4 [2] 76 f1 [2] 58 f1 [2] 67 ed }

  condition:
    any of them
}