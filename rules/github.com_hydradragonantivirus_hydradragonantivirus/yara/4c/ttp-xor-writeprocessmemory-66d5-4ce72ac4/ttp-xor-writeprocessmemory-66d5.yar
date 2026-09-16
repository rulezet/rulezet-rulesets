rule TTP_XOR_WriteProcessMemory_66d5 {
  strings:
    $key_66d5 = { 31 a7 [2] 03 85 [2] 05 b0 [2] 2b b0 [2] 14 ac }

  condition:
    any of them
}