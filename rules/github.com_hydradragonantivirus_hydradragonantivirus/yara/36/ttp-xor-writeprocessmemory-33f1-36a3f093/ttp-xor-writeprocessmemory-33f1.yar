rule TTP_XOR_WriteProcessMemory_33f1 {
  strings:
    $key_33f1 = { 64 83 [2] 56 a1 [2] 50 94 [2] 7e 94 [2] 41 88 }

  condition:
    any of them
}