rule TTP_XOR_WriteProcessMemory_3556 {
  strings:
    $key_3556 = { 62 24 [2] 50 06 [2] 56 33 [2] 78 33 [2] 47 2f }

  condition:
    any of them
}