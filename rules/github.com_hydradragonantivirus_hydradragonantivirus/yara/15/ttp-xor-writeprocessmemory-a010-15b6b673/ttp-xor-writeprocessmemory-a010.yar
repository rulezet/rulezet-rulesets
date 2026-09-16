rule TTP_XOR_WriteProcessMemory_a010 {
  strings:
    $key_a010 = { f7 62 [2] c5 40 [2] c3 75 [2] ed 75 [2] d2 69 }

  condition:
    any of them
}