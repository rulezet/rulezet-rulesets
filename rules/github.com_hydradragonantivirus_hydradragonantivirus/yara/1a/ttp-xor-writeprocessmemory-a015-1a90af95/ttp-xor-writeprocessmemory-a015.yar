rule TTP_XOR_WriteProcessMemory_a015 {
  strings:
    $key_a015 = { f7 67 [2] c5 45 [2] c3 70 [2] ed 70 [2] d2 6c }

  condition:
    any of them
}