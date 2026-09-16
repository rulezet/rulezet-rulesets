rule TTP_XOR_WriteProcessMemory_c6b2 {
  strings:
    $key_c6b2 = { 91 c0 [2] a3 e2 [2] a5 d7 [2] 8b d7 [2] b4 cb }

  condition:
    any of them
}