rule TTP_XOR_WriteProcessMemory_45e7 {
  strings:
    $key_45e7 = { 12 95 [2] 20 b7 [2] 26 82 [2] 08 82 [2] 37 9e }

  condition:
    any of them
}