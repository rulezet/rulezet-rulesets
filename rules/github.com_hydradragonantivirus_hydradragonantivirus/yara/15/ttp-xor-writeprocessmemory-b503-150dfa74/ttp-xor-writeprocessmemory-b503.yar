rule TTP_XOR_WriteProcessMemory_b503 {
  strings:
    $key_b503 = { e2 71 [2] d0 53 [2] d6 66 [2] f8 66 [2] c7 7a }

  condition:
    any of them
}