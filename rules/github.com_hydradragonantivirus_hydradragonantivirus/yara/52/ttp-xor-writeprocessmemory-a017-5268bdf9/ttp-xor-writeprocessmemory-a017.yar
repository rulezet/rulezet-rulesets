rule TTP_XOR_WriteProcessMemory_a017 {
  strings:
    $key_a017 = { f7 65 [2] c5 47 [2] c3 72 [2] ed 72 [2] d2 6e }

  condition:
    any of them
}