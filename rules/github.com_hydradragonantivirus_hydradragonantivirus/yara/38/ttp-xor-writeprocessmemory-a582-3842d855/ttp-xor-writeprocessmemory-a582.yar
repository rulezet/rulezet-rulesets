rule TTP_XOR_WriteProcessMemory_a582 {
  strings:
    $key_a582 = { f2 f0 [2] c0 d2 [2] c6 e7 [2] e8 e7 [2] d7 fb }

  condition:
    any of them
}