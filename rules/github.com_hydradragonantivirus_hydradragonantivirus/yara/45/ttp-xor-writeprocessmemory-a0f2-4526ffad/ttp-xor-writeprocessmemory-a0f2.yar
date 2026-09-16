rule TTP_XOR_WriteProcessMemory_a0f2 {
  strings:
    $key_a0f2 = { f7 80 [2] c5 a2 [2] c3 97 [2] ed 97 [2] d2 8b }

  condition:
    any of them
}