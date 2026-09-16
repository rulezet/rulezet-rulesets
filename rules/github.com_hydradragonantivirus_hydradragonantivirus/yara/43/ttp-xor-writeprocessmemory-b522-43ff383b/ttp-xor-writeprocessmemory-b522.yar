rule TTP_XOR_WriteProcessMemory_b522 {
  strings:
    $key_b522 = { e2 50 [2] d0 72 [2] d6 47 [2] f8 47 [2] c7 5b }

  condition:
    any of them
}