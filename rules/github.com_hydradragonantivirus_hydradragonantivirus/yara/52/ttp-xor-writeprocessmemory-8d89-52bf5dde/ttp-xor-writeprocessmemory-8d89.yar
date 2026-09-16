rule TTP_XOR_WriteProcessMemory_8d89 {
  strings:
    $key_8d89 = { da fb [2] e8 d9 [2] ee ec [2] c0 ec [2] ff f0 }

  condition:
    any of them
}