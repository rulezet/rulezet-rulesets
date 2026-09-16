rule TTP_XOR_WriteProcessMemory_a675 {
  strings:
    $key_a675 = { f1 07 [2] c3 25 [2] c5 10 [2] eb 10 [2] d4 0c }

  condition:
    any of them
}