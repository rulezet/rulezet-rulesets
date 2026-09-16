rule TTP_XOR_WriteProcessMemory_e3b2 {
  strings:
    $key_e3b2 = { b4 c0 [2] 86 e2 [2] 80 d7 [2] ae d7 [2] 91 cb }

  condition:
    any of them
}