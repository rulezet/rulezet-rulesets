rule TTP_XOR_WriteProcessMemory_b445 {
  strings:
    $key_b445 = { e3 37 [2] d1 15 [2] d7 20 [2] f9 20 [2] c6 3c }

  condition:
    any of them
}