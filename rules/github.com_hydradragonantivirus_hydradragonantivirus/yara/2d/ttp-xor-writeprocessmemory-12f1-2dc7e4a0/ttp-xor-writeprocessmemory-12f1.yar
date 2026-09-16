rule TTP_XOR_WriteProcessMemory_12f1 {
  strings:
    $key_12f1 = { 45 83 [2] 77 a1 [2] 71 94 [2] 5f 94 [2] 60 88 }

  condition:
    any of them
}