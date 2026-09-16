rule TTP_XOR_WriteProcessMemory_8612 {
  strings:
    $key_8612 = { d1 60 [2] e3 42 [2] e5 77 [2] cb 77 [2] f4 6b }

  condition:
    any of them
}