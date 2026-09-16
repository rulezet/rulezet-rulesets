rule TTP_XOR_WriteProcessMemory_a022 {
  strings:
    $key_a022 = { f7 50 [2] c5 72 [2] c3 47 [2] ed 47 [2] d2 5b }

  condition:
    any of them
}