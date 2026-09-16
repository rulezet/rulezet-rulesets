rule TTP_XOR_WriteProcessMemory_b515 {
  strings:
    $key_b515 = { e2 67 [2] d0 45 [2] d6 70 [2] f8 70 [2] c7 6c }

  condition:
    any of them
}