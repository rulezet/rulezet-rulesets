rule TTP_XOR_WriteProcessMemory_a689 {
  strings:
    $key_a689 = { f1 fb [2] c3 d9 [2] c5 ec [2] eb ec [2] d4 f0 }

  condition:
    any of them
}