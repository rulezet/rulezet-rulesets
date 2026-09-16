rule TTP_XOR_WriteProcessMemory_78c3 {
  strings:
    $key_78c3 = { 2f b1 [2] 1d 93 [2] 1b a6 [2] 35 a6 [2] 0a ba }

  condition:
    any of them
}