rule TTP_XOR_WriteProcessMemory_e527 {
  strings:
    $key_e527 = { b2 55 [2] 80 77 [2] 86 42 [2] a8 42 [2] 97 5e }

  condition:
    any of them
}