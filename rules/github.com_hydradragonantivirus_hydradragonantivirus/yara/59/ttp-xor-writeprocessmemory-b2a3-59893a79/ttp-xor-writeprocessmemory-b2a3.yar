rule TTP_XOR_WriteProcessMemory_b2a3 {
  strings:
    $key_b2a3 = { e5 d1 [2] d7 f3 [2] d1 c6 [2] ff c6 [2] c0 da }

  condition:
    any of them
}