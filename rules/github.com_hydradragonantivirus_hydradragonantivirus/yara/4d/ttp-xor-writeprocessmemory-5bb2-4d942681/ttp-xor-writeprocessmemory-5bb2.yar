rule TTP_XOR_WriteProcessMemory_5bb2 {
  strings:
    $key_5bb2 = { 0c c0 [2] 3e e2 [2] 38 d7 [2] 16 d7 [2] 29 cb }

  condition:
    any of them
}