rule TTP_XOR_WriteProcessMemory_a489 {
  strings:
    $key_a489 = { f3 fb [2] c1 d9 [2] c7 ec [2] e9 ec [2] d6 f0 }

  condition:
    any of them
}