rule TTP_XOR_WriteProcessMemory_b567 {
  strings:
    $key_b567 = { e2 15 [2] d0 37 [2] d6 02 [2] f8 02 [2] c7 1e }

  condition:
    any of them
}