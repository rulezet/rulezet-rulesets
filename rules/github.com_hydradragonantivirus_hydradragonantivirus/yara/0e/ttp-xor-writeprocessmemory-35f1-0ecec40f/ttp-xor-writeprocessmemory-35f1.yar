rule TTP_XOR_WriteProcessMemory_35f1 {
  strings:
    $key_35f1 = { 62 83 [2] 50 a1 [2] 56 94 [2] 78 94 [2] 47 88 }

  condition:
    any of them
}