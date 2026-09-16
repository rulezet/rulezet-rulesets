rule TTP_XOR_WriteProcessMemory_30f1 {
  strings:
    $key_30f1 = { 67 83 [2] 55 a1 [2] 53 94 [2] 7d 94 [2] 42 88 }

  condition:
    any of them
}