rule TTP_XOR_WriteProcessMemory_b2b2 {
  strings:
    $key_b2b2 = { e5 c0 [2] d7 e2 [2] d1 d7 [2] ff d7 [2] c0 cb }

  condition:
    any of them
}