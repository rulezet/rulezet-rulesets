rule TTP_XOR_WriteProcessMemory_b507 {
  strings:
    $key_b507 = { e2 75 [2] d0 57 [2] d6 62 [2] f8 62 [2] c7 7e }

  condition:
    any of them
}