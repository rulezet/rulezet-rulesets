rule TTP_XOR_WriteProcessMemory_63e9 {
  strings:
    $key_63e9 = { 34 9b [2] 06 b9 [2] 00 8c [2] 2e 8c [2] 11 90 }

  condition:
    any of them
}