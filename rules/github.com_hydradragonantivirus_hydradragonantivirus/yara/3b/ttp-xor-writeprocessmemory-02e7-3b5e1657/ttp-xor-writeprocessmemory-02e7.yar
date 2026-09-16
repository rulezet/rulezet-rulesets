rule TTP_XOR_WriteProcessMemory_02e7 {
  strings:
    $key_02e7 = { 55 95 [2] 67 b7 [2] 61 82 [2] 4f 82 [2] 70 9e }

  condition:
    any of them
}