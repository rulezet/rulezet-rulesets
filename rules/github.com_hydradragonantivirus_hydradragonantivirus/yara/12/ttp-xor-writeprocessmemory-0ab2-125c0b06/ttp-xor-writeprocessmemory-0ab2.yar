rule TTP_XOR_WriteProcessMemory_0ab2 {
  strings:
    $key_0ab2 = { 5d c0 [2] 6f e2 [2] 69 d7 [2] 47 d7 [2] 78 cb }

  condition:
    any of them
}