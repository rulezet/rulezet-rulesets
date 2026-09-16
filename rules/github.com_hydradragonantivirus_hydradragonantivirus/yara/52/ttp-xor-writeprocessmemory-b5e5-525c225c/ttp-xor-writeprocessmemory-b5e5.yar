rule TTP_XOR_WriteProcessMemory_b5e5 {
  strings:
    $key_b5e5 = { e2 97 [2] d0 b5 [2] d6 80 [2] f8 80 [2] c7 9c }

  condition:
    any of them
}