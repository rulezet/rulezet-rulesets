rule TTP_XOR_WriteProcessMemory_8215 {
  strings:
    $key_8215 = { d5 67 [2] e7 45 [2] e1 70 [2] cf 70 [2] f0 6c }

  condition:
    any of them
}