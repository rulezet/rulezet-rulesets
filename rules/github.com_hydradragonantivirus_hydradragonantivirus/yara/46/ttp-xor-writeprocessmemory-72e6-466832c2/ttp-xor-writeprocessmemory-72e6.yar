rule TTP_XOR_WriteProcessMemory_72e6 {
  strings:
    $key_72e6 = { 25 94 [2] 17 b6 [2] 11 83 [2] 3f 83 [2] 00 9f }

  condition:
    any of them
}