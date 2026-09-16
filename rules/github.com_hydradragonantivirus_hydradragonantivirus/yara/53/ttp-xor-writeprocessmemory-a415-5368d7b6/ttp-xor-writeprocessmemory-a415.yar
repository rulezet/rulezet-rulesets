rule TTP_XOR_WriteProcessMemory_a415 {
  strings:
    $key_a415 = { f3 67 [2] c1 45 [2] c7 70 [2] e9 70 [2] d6 6c }

  condition:
    any of them
}