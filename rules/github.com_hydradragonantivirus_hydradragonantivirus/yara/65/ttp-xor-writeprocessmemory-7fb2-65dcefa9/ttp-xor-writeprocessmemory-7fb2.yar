rule TTP_XOR_WriteProcessMemory_7fb2 {
  strings:
    $key_7fb2 = { 28 c0 [2] 1a e2 [2] 1c d7 [2] 32 d7 [2] 0d cb }

  condition:
    any of them
}