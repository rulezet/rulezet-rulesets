rule TTP_XOR_WriteProcessMemory_7222 {
  strings:
    $key_7222 = { 25 50 [2] 17 72 [2] 11 47 [2] 3f 47 [2] 00 5b }

  condition:
    any of them
}