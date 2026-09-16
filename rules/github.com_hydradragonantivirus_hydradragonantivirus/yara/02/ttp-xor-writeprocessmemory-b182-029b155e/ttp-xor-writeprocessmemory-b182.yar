rule TTP_XOR_WriteProcessMemory_b182 {
  strings:
    $key_b182 = { e6 f0 [2] d4 d2 [2] d2 e7 [2] fc e7 [2] c3 fb }

  condition:
    any of them
}