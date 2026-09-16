rule TTP_XOR_WriteProcessMemory_32b2 {
  strings:
    $key_32b2 = { 65 c0 [2] 57 e2 [2] 51 d7 [2] 7f d7 [2] 40 cb }

  condition:
    any of them
}