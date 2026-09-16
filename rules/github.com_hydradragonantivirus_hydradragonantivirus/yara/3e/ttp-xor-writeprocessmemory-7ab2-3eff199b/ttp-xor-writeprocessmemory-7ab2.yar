rule TTP_XOR_WriteProcessMemory_7ab2 {
  strings:
    $key_7ab2 = { 2d c0 [2] 1f e2 [2] 19 d7 [2] 37 d7 [2] 08 cb }

  condition:
    any of them
}