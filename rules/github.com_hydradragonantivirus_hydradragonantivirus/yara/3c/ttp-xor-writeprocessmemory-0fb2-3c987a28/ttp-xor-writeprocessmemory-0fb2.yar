rule TTP_XOR_WriteProcessMemory_0fb2 {
  strings:
    $key_0fb2 = { 58 c0 [2] 6a e2 [2] 6c d7 [2] 42 d7 [2] 7d cb }

  condition:
    any of them
}