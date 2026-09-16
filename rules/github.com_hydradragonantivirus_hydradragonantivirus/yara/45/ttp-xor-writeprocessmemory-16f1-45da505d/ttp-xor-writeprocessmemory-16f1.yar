rule TTP_XOR_WriteProcessMemory_16f1 {
  strings:
    $key_16f1 = { 41 83 [2] 73 a1 [2] 75 94 [2] 5b 94 [2] 64 88 }

  condition:
    any of them
}