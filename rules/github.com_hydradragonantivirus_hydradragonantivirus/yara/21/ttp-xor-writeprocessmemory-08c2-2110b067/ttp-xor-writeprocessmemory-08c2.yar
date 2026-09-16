rule TTP_XOR_WriteProcessMemory_08c2 {
  strings:
    $key_08c2 = { 5f b0 [2] 6d 92 [2] 6b a7 [2] 45 a7 [2] 7a bb }

  condition:
    any of them
}