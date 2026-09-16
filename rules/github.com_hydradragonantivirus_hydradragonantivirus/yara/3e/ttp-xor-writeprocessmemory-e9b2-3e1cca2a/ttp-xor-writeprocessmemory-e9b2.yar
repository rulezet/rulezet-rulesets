rule TTP_XOR_WriteProcessMemory_e9b2 {
  strings:
    $key_e9b2 = { be c0 [2] 8c e2 [2] 8a d7 [2] a4 d7 [2] 9b cb }

  condition:
    any of them
}