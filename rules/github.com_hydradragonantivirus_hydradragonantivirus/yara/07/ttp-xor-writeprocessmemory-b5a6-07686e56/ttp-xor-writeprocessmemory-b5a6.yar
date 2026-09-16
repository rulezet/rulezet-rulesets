rule TTP_XOR_WriteProcessMemory_b5a6 {
  strings:
    $key_b5a6 = { e2 d4 [2] d0 f6 [2] d6 c3 [2] f8 c3 [2] c7 df }

  condition:
    any of them
}