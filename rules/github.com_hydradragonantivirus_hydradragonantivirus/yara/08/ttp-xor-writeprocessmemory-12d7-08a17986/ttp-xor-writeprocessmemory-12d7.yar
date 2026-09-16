rule TTP_XOR_WriteProcessMemory_12d7 {
  strings:
    $key_12d7 = { 45 a5 [2] 77 87 [2] 71 b2 [2] 5f b2 [2] 60 ae }

  condition:
    any of them
}