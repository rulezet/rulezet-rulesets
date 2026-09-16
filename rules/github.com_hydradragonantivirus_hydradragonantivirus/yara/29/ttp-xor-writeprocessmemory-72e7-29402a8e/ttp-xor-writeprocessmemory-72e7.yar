rule TTP_XOR_WriteProcessMemory_72e7 {
  strings:
    $key_72e7 = { 25 95 [2] 17 b7 [2] 11 82 [2] 3f 82 [2] 00 9e }

  condition:
    any of them
}