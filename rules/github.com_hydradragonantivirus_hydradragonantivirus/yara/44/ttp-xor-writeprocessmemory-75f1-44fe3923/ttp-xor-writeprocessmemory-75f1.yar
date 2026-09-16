rule TTP_XOR_WriteProcessMemory_75f1 {
  strings:
    $key_75f1 = { 22 83 [2] 10 a1 [2] 16 94 [2] 38 94 [2] 07 88 }

  condition:
    any of them
}