rule TTP_XOR_WriteProcessMemory_50b2 {
  strings:
    $key_50b2 = { 07 c0 [2] 35 e2 [2] 33 d7 [2] 1d d7 [2] 22 cb }

  condition:
    any of them
}