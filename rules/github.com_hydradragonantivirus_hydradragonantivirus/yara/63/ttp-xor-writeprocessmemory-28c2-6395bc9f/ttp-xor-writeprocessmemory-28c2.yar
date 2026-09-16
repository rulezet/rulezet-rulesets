rule TTP_XOR_WriteProcessMemory_28c2 {
  strings:
    $key_28c2 = { 7f b0 [2] 4d 92 [2] 4b a7 [2] 65 a7 [2] 5a bb }

  condition:
    any of them
}