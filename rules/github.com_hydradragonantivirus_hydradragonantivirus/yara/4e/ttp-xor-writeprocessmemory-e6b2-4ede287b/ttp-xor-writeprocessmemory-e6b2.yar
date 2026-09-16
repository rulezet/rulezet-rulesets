rule TTP_XOR_WriteProcessMemory_e6b2 {
  strings:
    $key_e6b2 = { b1 c0 [2] 83 e2 [2] 85 d7 [2] ab d7 [2] 94 cb }

  condition:
    any of them
}