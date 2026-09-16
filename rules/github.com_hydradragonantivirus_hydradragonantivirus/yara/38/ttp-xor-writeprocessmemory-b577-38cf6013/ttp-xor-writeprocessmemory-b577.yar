rule TTP_XOR_WriteProcessMemory_b577 {
  strings:
    $key_b577 = { e2 05 [2] d0 27 [2] d6 12 [2] f8 12 [2] c7 0e }

  condition:
    any of them
}