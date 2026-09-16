rule TTP_XOR_WriteProcessMemory_28c3 {
  strings:
    $key_28c3 = { 7f b1 [2] 4d 93 [2] 4b a6 [2] 65 a6 [2] 5a ba }

  condition:
    any of them
}