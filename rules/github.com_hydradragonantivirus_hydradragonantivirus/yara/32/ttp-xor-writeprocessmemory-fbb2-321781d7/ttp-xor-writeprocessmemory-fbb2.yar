rule TTP_XOR_WriteProcessMemory_fbb2 {
  strings:
    $key_fbb2 = { ac c0 [2] 9e e2 [2] 98 d7 [2] b6 d7 [2] 89 cb }

  condition:
    any of them
}