rule TTP_XOR_WriteProcessMemory_56e7 {
  strings:
    $key_56e7 = { 01 95 [2] 33 b7 [2] 35 82 [2] 1b 82 [2] 24 9e }

  condition:
    any of them
}