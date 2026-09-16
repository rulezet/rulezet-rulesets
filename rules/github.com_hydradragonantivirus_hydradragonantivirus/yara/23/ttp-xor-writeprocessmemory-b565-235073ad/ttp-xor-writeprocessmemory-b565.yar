rule TTP_XOR_WriteProcessMemory_b565 {
  strings:
    $key_b565 = { e2 17 [2] d0 35 [2] d6 00 [2] f8 00 [2] c7 1c }

  condition:
    any of them
}