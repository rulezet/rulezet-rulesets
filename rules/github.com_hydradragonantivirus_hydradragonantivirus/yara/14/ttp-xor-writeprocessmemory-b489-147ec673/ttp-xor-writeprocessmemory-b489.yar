rule TTP_XOR_WriteProcessMemory_b489 {
  strings:
    $key_b489 = { e3 fb [2] d1 d9 [2] d7 ec [2] f9 ec [2] c6 f0 }

  condition:
    any of them
}