rule TTP_XOR_WriteProcessMemory_e1b2 {
  strings:
    $key_e1b2 = { b6 c0 [2] 84 e2 [2] 82 d7 [2] ac d7 [2] 93 cb }

  condition:
    any of them
}