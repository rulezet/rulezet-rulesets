rule TTP_XOR_WriteProcessMemory_62b2 {
  strings:
    $key_62b2 = { 35 c0 [2] 07 e2 [2] 01 d7 [2] 2f d7 [2] 10 cb }

  condition:
    any of them
}