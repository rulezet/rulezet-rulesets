rule TTP_XOR_WriteProcessMemory_6bb2 {
  strings:
    $key_6bb2 = { 3c c0 [2] 0e e2 [2] 08 d7 [2] 26 d7 [2] 19 cb }

  condition:
    any of them
}