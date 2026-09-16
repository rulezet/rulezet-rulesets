rule TTP_XOR_WriteProcessMemory_a002 {
  strings:
    $key_a002 = { f7 70 [2] c5 52 [2] c3 67 [2] ed 67 [2] d2 7b }

  condition:
    any of them
}