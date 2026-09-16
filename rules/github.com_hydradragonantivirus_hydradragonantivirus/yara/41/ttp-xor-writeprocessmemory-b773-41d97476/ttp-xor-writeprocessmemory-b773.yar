rule TTP_XOR_WriteProcessMemory_b773 {
  strings:
    $key_b773 = { e0 01 [2] d2 23 [2] d4 16 [2] fa 16 [2] c5 0a }

  condition:
    any of them
}