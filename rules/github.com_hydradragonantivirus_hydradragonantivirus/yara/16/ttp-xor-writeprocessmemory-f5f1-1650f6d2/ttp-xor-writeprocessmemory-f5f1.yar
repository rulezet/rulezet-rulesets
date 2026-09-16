rule TTP_XOR_WriteProcessMemory_f5f1 {
  strings:
    $key_f5f1 = { a2 83 [2] 90 a1 [2] 96 94 [2] b8 94 [2] 87 88 }

  condition:
    any of them
}