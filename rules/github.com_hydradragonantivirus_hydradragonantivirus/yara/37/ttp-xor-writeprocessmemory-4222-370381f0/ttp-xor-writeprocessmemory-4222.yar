rule TTP_XOR_WriteProcessMemory_4222 {
  strings:
    $key_4222 = { 15 50 [2] 27 72 [2] 21 47 [2] 0f 47 [2] 30 5b }

  condition:
    any of them
}