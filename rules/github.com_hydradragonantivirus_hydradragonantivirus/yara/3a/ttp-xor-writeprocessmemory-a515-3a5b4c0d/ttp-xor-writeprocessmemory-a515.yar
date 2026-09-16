rule TTP_XOR_WriteProcessMemory_a515 {
  strings:
    $key_a515 = { f2 67 [2] c0 45 [2] c6 70 [2] e8 70 [2] d7 6c }

  condition:
    any of them
}