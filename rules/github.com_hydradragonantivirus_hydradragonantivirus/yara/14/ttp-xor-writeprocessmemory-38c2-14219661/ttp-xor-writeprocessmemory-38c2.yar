rule TTP_XOR_WriteProcessMemory_38c2 {
  strings:
    $key_38c2 = { 6f b0 [2] 5d 92 [2] 5b a7 [2] 75 a7 [2] 4a bb }

  condition:
    any of them
}