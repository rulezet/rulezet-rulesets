rule TTP_XOR_WriteProcessMemory_a045 {
  strings:
    $key_a045 = { f7 37 [2] c5 15 [2] c3 20 [2] ed 20 [2] d2 3c }

  condition:
    any of them
}