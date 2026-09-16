rule TTP_XOR_WriteProcessMemory_72e9 {
  strings:
    $key_72e9 = { 25 9b [2] 17 b9 [2] 11 8c [2] 3f 8c [2] 00 90 }

  condition:
    any of them
}