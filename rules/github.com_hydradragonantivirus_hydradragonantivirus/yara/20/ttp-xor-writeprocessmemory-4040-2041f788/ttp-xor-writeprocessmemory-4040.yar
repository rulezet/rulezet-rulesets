rule TTP_XOR_WriteProcessMemory_4040 {
  strings:
    $key_4040 = { 17 32 [2] 25 10 [2] 23 25 [2] 0d 25 [2] 32 39 }

  condition:
    any of them
}