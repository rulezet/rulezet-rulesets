rule TTP_XOR_WriteProcessMemory_a505 {
  strings:
    $key_a505 = { f2 77 [2] c0 55 [2] c6 60 [2] e8 60 [2] d7 7c }

  condition:
    any of them
}