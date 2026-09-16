rule TTP_XOR_WriteProcessMemory_5ab2 {
  strings:
    $key_5ab2 = { 0d c0 [2] 3f e2 [2] 39 d7 [2] 17 d7 [2] 28 cb }

  condition:
    any of them
}