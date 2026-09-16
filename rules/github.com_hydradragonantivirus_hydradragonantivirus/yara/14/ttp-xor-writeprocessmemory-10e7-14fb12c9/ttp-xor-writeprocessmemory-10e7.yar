rule TTP_XOR_WriteProcessMemory_10e7 {
  strings:
    $key_10e7 = { 47 95 [2] 75 b7 [2] 73 82 [2] 5d 82 [2] 62 9e }

  condition:
    any of them
}