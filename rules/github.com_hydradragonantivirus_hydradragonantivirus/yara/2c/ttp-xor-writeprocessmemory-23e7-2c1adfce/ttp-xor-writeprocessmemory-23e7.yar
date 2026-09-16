rule TTP_XOR_WriteProcessMemory_23e7 {
  strings:
    $key_23e7 = { 74 95 [2] 46 b7 [2] 40 82 [2] 6e 82 [2] 51 9e }

  condition:
    any of them
}