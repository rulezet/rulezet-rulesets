rule TTP_XOR_WriteProcessMemory_b180 {
  strings:
    $key_b180 = { e6 f2 [2] d4 d0 [2] d2 e5 [2] fc e5 [2] c3 f9 }

  condition:
    any of them
}