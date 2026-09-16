rule TTP_XOR_WriteProcessMemory_79b2 {
  strings:
    $key_79b2 = { 2e c0 [2] 1c e2 [2] 1a d7 [2] 34 d7 [2] 0b cb }

  condition:
    any of them
}