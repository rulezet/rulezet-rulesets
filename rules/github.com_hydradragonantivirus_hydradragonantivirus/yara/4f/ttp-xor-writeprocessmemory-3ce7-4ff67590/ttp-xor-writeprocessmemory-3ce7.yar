rule TTP_XOR_WriteProcessMemory_3ce7 {
  strings:
    $key_3ce7 = { 6b 95 [2] 59 b7 [2] 5f 82 [2] 71 82 [2] 4e 9e }

  condition:
    any of them
}