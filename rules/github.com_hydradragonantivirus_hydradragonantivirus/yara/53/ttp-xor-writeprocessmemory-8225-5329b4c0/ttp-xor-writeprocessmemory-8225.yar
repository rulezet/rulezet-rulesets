rule TTP_XOR_WriteProcessMemory_8225 {
  strings:
    $key_8225 = { d5 57 [2] e7 75 [2] e1 40 [2] cf 40 [2] f0 5c }

  condition:
    any of them
}