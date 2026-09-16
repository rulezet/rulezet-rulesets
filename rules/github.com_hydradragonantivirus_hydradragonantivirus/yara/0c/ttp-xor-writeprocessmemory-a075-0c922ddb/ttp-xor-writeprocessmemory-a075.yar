rule TTP_XOR_WriteProcessMemory_a075 {
  strings:
    $key_a075 = { f7 07 [2] c5 25 [2] c3 10 [2] ed 10 [2] d2 0c }

  condition:
    any of them
}