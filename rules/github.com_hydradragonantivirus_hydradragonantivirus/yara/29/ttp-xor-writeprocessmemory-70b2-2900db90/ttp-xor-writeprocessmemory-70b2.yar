rule TTP_XOR_WriteProcessMemory_70b2 {
  strings:
    $key_70b2 = { 27 c0 [2] 15 e2 [2] 13 d7 [2] 3d d7 [2] 02 cb }

  condition:
    any of them
}