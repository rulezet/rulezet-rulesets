rule TTP_XOR_WriteProcessMemory_a031 {
  strings:
    $key_a031 = { f7 43 [2] c5 61 [2] c3 54 [2] ed 54 [2] d2 48 }

  condition:
    any of them
}