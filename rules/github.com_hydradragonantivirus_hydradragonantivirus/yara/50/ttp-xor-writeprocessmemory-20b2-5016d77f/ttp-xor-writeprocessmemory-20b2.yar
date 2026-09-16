rule TTP_XOR_WriteProcessMemory_20b2 {
  strings:
    $key_20b2 = { 77 c0 [2] 45 e2 [2] 43 d7 [2] 6d d7 [2] 52 cb }

  condition:
    any of them
}