rule TTP_XOR_WriteProcessMemory_b4a6 {
  strings:
    $key_b4a6 = { e3 d4 [2] d1 f6 [2] d7 c3 [2] f9 c3 [2] c6 df }

  condition:
    any of them
}