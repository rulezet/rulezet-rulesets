rule TTP_XOR_WriteProcessMemory_43b2 {
  strings:
    $key_43b2 = { 14 c0 [2] 26 e2 [2] 20 d7 [2] 0e d7 [2] 31 cb }

  condition:
    any of them
}