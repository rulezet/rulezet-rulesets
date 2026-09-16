rule TTP_XOR_WriteProcessMemory_b289 {
  strings:
    $key_b289 = { e5 fb [2] d7 d9 [2] d1 ec [2] ff ec [2] c0 f0 }

  condition:
    any of them
}