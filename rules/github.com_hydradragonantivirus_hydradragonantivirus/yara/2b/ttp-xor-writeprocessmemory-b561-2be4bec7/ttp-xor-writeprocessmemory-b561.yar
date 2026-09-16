rule TTP_XOR_WriteProcessMemory_b561 {
  strings:
    $key_b561 = { e2 13 [2] d0 31 [2] d6 04 [2] f8 04 [2] c7 18 }

  condition:
    any of them
}