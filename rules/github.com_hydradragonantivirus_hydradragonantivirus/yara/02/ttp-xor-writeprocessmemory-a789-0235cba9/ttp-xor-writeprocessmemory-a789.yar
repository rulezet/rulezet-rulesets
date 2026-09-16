rule TTP_XOR_WriteProcessMemory_a789 {
  strings:
    $key_a789 = { f0 fb [2] c2 d9 [2] c4 ec [2] ea ec [2] d5 f0 }

  condition:
    any of them
}