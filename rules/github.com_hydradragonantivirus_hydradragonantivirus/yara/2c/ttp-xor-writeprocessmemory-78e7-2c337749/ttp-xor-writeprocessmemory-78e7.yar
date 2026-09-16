rule TTP_XOR_WriteProcessMemory_78e7 {
  strings:
    $key_78e7 = { 2f 95 [2] 1d b7 [2] 1b 82 [2] 35 82 [2] 0a 9e }

  condition:
    any of them
}