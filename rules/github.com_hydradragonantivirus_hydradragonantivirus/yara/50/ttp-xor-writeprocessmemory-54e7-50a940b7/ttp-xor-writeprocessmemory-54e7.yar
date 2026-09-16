rule TTP_XOR_WriteProcessMemory_54e7 {
  strings:
    $key_54e7 = { 03 95 [2] 31 b7 [2] 37 82 [2] 19 82 [2] 26 9e }

  condition:
    any of them
}