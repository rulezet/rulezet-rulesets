rule TTP_XOR_WriteProcessMemory_b191 {
  strings:
    $key_b191 = { e6 e3 [2] d4 c1 [2] d2 f4 [2] fc f4 [2] c3 e8 }

  condition:
    any of them
}