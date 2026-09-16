rule TTP_XOR_WriteProcessMemory_72b2 {
  strings:
    $key_72b2 = { 25 c0 [2] 17 e2 [2] 11 d7 [2] 3f d7 [2] 00 cb }

  condition:
    any of them
}