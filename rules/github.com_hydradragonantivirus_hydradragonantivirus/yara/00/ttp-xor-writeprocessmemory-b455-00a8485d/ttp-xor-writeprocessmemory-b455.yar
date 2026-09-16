rule TTP_XOR_WriteProcessMemory_b455 {
  strings:
    $key_b455 = { e3 27 [2] d1 05 [2] d7 30 [2] f9 30 [2] c6 2c }

  condition:
    any of them
}