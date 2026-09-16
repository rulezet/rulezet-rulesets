rule TTP_XOR_WriteProcessMemory_20d7 {
  strings:
    $key_20d7 = { 77 a5 [2] 45 87 [2] 43 b2 [2] 6d b2 [2] 52 ae }

  condition:
    any of them
}