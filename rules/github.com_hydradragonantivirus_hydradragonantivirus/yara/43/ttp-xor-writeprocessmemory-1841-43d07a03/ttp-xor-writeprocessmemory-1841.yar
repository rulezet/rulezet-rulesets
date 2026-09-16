rule TTP_XOR_WriteProcessMemory_1841 {
  strings:
    $key_1841 = { 4f 33 [2] 7d 11 [2] 7b 24 [2] 55 24 [2] 6a 38 }

  condition:
    any of them
}