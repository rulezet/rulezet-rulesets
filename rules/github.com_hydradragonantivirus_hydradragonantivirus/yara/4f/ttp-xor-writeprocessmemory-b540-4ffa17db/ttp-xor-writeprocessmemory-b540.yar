rule TTP_XOR_WriteProcessMemory_b540 {
  strings:
    $key_b540 = { e2 32 [2] d0 10 [2] d6 25 [2] f8 25 [2] c7 39 }

  condition:
    any of them
}