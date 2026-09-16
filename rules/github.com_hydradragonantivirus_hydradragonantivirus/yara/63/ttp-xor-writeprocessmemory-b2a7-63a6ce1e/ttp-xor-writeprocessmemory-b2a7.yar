rule TTP_XOR_WriteProcessMemory_b2a7 {
  strings:
    $key_b2a7 = { e5 d5 [2] d7 f7 [2] d1 c2 [2] ff c2 [2] c0 de }

  condition:
    any of them
}