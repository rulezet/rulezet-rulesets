rule TTP_XOR_WriteProcessMemory_b189 {
  strings:
    $key_b189 = { e6 fb [2] d4 d9 [2] d2 ec [2] fc ec [2] c3 f0 }

  condition:
    any of them
}