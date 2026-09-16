rule TTP_XOR_WriteProcessMemory_00b2 {
  strings:
    $key_00b2 = { 57 c0 [2] 65 e2 [2] 63 d7 [2] 4d d7 [2] 72 cb }

  condition:
    any of them
}