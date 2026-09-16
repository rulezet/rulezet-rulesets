rule TTP_XOR_WriteProcessMemory_b2b4 {
  strings:
    $key_b2b4 = { e5 c6 [2] d7 e4 [2] d1 d1 [2] ff d1 [2] c0 cd }

  condition:
    any of them
}