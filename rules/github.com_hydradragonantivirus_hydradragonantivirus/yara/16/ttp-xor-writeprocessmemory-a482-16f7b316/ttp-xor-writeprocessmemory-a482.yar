rule TTP_XOR_WriteProcessMemory_a482 {
  strings:
    $key_a482 = { f3 f0 [2] c1 d2 [2] c7 e7 [2] e9 e7 [2] d6 fb }

  condition:
    any of them
}