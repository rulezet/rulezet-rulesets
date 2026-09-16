rule TTP_XOR_WriteProcessMemory_8273 {
  strings:
    $key_8273 = { d5 01 [2] e7 23 [2] e1 16 [2] cf 16 [2] f0 0a }

  condition:
    any of them
}