rule TTP_XOR_WriteProcessMemory_1ab2 {
  strings:
    $key_1ab2 = { 4d c0 [2] 7f e2 [2] 79 d7 [2] 57 d7 [2] 68 cb }

  condition:
    any of them
}