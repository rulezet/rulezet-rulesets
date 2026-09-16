rule TTP_XOR_WriteProcessMemory_64b2 {
  strings:
    $key_64b2 = { 33 c0 [2] 01 e2 [2] 07 d7 [2] 29 d7 [2] 16 cb }

  condition:
    any of them
}