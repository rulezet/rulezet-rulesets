rule TTP_XOR_WriteProcessMemory_b487 {
  strings:
    $key_b487 = { e3 f5 [2] d1 d7 [2] d7 e2 [2] f9 e2 [2] c6 fe }

  condition:
    any of them
}