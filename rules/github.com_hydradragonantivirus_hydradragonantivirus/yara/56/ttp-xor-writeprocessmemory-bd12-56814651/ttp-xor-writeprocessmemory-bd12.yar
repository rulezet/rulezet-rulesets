rule TTP_XOR_WriteProcessMemory_bd12 {
  strings:
    $key_bd12 = { ea 60 [2] d8 42 [2] de 77 [2] f0 77 [2] cf 6b }

  condition:
    any of them
}