rule TTP_XOR_WriteProcessMemory_18c3 {
  strings:
    $key_18c3 = { 4f b1 [2] 7d 93 [2] 7b a6 [2] 55 a6 [2] 6a ba }

  condition:
    any of them
}