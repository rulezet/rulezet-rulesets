rule TTP_XOR_WriteProcessMemory_0842 {
  strings:
    $key_0842 = { 5f 30 [2] 6d 12 [2] 6b 27 [2] 45 27 [2] 7a 3b }

  condition:
    any of them
}