rule TTP_XOR_WriteProcessMemory_46f1 {
  strings:
    $key_46f1 = { 11 83 [2] 23 a1 [2] 25 94 [2] 0b 94 [2] 34 88 }

  condition:
    any of them
}