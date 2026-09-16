rule TTP_XOR_WriteProcessMemory_22d7 {
  strings:
    $key_22d7 = { 75 a5 [2] 47 87 [2] 41 b2 [2] 6f b2 [2] 50 ae }

  condition:
    any of them
}