rule TTP_XOR_WriteProcessMemory_b382 {
  strings:
    $key_b382 = { e4 f0 [2] d6 d2 [2] d0 e7 [2] fe e7 [2] c1 fb }

  condition:
    any of them
}