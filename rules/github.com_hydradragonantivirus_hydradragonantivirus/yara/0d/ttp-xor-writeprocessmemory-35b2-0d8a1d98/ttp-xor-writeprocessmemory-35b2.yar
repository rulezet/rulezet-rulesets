rule TTP_XOR_WriteProcessMemory_35b2 {
  strings:
    $key_35b2 = { 62 c0 [2] 50 e2 [2] 56 d7 [2] 78 d7 [2] 47 cb }

  condition:
    any of them
}