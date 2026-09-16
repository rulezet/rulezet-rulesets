rule TTP_XOR_WriteProcessMemory_b285 {
  strings:
    $key_b285 = { e5 f7 [2] d7 d5 [2] d1 e0 [2] ff e0 [2] c0 fc }

  condition:
    any of them
}