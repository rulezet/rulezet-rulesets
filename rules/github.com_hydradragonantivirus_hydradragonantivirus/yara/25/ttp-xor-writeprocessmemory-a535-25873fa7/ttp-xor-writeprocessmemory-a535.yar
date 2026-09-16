rule TTP_XOR_WriteProcessMemory_a535 {
  strings:
    $key_a535 = { f2 47 [2] c0 65 [2] c6 50 [2] e8 50 [2] d7 4c }

  condition:
    any of them
}