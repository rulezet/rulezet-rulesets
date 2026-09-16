rule TTP_XOR_WriteProcessMemory_13f1 {
  strings:
    $key_13f1 = { 44 83 [2] 76 a1 [2] 70 94 [2] 5e 94 [2] 61 88 }

  condition:
    any of them
}