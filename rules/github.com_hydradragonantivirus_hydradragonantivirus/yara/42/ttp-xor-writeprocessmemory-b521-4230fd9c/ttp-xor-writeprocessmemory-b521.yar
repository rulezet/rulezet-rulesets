rule TTP_XOR_WriteProcessMemory_b521 {
  strings:
    $key_b521 = { e2 53 [2] d0 71 [2] d6 44 [2] f8 44 [2] c7 58 }

  condition:
    any of them
}