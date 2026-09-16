rule TTP_XOR_WriteProcessMemory_b4a5 {
  strings:
    $key_b4a5 = { e3 d7 [2] d1 f5 [2] d7 c0 [2] f9 c0 [2] c6 dc }

  condition:
    any of them
}