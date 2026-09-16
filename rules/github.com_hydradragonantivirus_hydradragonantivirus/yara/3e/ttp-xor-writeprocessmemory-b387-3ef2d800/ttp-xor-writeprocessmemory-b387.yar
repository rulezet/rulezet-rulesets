rule TTP_XOR_WriteProcessMemory_b387 {
  strings:
    $key_b387 = { e4 f5 [2] d6 d7 [2] d0 e2 [2] fe e2 [2] c1 fe }

  condition:
    any of them
}