rule TTP_XOR_WriteProcessMemory_e7f1 {
  strings:
    $key_e7f1 = { b0 83 [2] 82 a1 [2] 84 94 [2] aa 94 [2] 95 88 }

  condition:
    any of them
}