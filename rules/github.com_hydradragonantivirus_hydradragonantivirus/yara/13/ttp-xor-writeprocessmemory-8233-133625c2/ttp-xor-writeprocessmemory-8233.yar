rule TTP_XOR_WriteProcessMemory_8233 {
  strings:
    $key_8233 = { d5 41 [2] e7 63 [2] e1 56 [2] cf 56 [2] f0 4a }

  condition:
    any of them
}