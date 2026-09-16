rule TTP_XOR_WriteProcessMemory_45b2 {
  strings:
    $key_45b2 = { 12 c0 [2] 20 e2 [2] 26 d7 [2] 08 d7 [2] 37 cb }

  condition:
    any of them
}