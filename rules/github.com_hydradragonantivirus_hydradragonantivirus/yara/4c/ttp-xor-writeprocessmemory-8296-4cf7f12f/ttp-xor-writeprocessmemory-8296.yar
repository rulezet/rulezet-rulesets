rule TTP_XOR_WriteProcessMemory_8296 {
  strings:
    $key_8296 = { d5 e4 [2] e7 c6 [2] e1 f3 [2] cf f3 [2] f0 ef }

  condition:
    any of them
}