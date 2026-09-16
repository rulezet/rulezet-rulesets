rule TTP_XOR_WriteProcessMemory_b405 {
  strings:
    $key_b405 = { e3 77 [2] d1 55 [2] d7 60 [2] f9 60 [2] c6 7c }

  condition:
    any of them
}