rule TTP_XOR_WriteProcessMemory_a0f1 {
  strings:
    $key_a0f1 = { f7 83 [2] c5 a1 [2] c3 94 [2] ed 94 [2] d2 88 }

  condition:
    any of them
}