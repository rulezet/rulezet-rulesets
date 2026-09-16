rule TTP_XOR_WriteProcessMemory_ebb2 {
  strings:
    $key_ebb2 = { bc c0 [2] 8e e2 [2] 88 d7 [2] a6 d7 [2] 99 cb }

  condition:
    any of them
}