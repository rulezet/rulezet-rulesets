rule TTP_XOR_WriteProcessMemory_b282 {
  strings:
    $key_b282 = { e5 f0 [2] d7 d2 [2] d1 e7 [2] ff e7 [2] c0 fb }

  condition:
    any of them
}