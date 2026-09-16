rule TTP_XOR_WriteProcessMemory_40e7 {
  strings:
    $key_40e7 = { 17 95 [2] 25 b7 [2] 23 82 [2] 0d 82 [2] 32 9e }

  condition:
    any of them
}