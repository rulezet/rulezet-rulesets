rule TTP_XOR_WriteProcessMemory_a425 {
  strings:
    $key_a425 = { f3 57 [2] c1 75 [2] c7 40 [2] e9 40 [2] d6 5c }

  condition:
    any of them
}