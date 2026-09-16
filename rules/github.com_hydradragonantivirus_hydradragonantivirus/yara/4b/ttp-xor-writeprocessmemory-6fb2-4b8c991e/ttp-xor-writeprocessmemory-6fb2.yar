rule TTP_XOR_WriteProcessMemory_6fb2 {
  strings:
    $key_6fb2 = { 38 c0 [2] 0a e2 [2] 0c d7 [2] 22 d7 [2] 1d cb }

  condition:
    any of them
}