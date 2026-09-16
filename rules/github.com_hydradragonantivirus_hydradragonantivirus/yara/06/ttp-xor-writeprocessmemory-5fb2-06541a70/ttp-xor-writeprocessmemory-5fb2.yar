rule TTP_XOR_WriteProcessMemory_5fb2 {
  strings:
    $key_5fb2 = { 08 c0 [2] 3a e2 [2] 3c d7 [2] 12 d7 [2] 2d cb }

  condition:
    any of them
}