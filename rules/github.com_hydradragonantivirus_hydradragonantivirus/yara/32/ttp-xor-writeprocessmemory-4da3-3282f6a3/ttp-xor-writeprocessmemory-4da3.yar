rule TTP_XOR_WriteProcessMemory_4da3 {
  strings:
    $key_4da3 = { 1a d1 [2] 28 f3 [2] 2e c6 [2] 00 c6 [2] 3f da }

  condition:
    any of them
}