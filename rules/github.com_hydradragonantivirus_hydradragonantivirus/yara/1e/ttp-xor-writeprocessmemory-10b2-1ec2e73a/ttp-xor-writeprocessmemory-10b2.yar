rule TTP_XOR_WriteProcessMemory_10b2 {
  strings:
    $key_10b2 = { 47 c0 [2] 75 e2 [2] 73 d7 [2] 5d d7 [2] 62 cb }

  condition:
    any of them
}