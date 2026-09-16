rule TTP_XOR_WriteProcessMemory_72e2 {
  strings:
    $key_72e2 = { 25 90 [2] 17 b2 [2] 11 87 [2] 3f 87 [2] 00 9b }

  condition:
    any of them
}