rule TTP_XOR_WriteProcessMemory_38c3 {
  strings:
    $key_38c3 = { 6f b1 [2] 5d 93 [2] 5b a6 [2] 75 a6 [2] 4a ba }

  condition:
    any of them
}