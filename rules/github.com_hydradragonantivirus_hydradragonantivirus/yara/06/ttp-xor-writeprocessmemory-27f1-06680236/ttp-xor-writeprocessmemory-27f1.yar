rule TTP_XOR_WriteProcessMemory_27f1 {
  strings:
    $key_27f1 = { 70 83 [2] 42 a1 [2] 44 94 [2] 6a 94 [2] 55 88 }

  condition:
    any of them
}