rule TTP_XOR_WriteProcessMemory_a040 {
  strings:
    $key_a040 = { f7 32 [2] c5 10 [2] c3 25 [2] ed 25 [2] d2 39 }

  condition:
    any of them
}