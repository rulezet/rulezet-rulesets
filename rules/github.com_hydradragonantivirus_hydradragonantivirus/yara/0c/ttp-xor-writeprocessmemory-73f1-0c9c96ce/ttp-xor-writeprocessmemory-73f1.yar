rule TTP_XOR_WriteProcessMemory_73f1 {
  strings:
    $key_73f1 = { 24 83 [2] 16 a1 [2] 10 94 [2] 3e 94 [2] 01 88 }

  condition:
    any of them
}