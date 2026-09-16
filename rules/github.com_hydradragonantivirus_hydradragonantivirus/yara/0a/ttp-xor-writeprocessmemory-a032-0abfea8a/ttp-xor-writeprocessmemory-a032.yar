rule TTP_XOR_WriteProcessMemory_a032 {
  strings:
    $key_a032 = { f7 40 [2] c5 62 [2] c3 57 [2] ed 57 [2] d2 4b }

  condition:
    any of them
}