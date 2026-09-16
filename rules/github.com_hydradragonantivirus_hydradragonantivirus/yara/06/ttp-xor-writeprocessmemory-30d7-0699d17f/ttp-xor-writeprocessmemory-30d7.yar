rule TTP_XOR_WriteProcessMemory_30d7 {
  strings:
    $key_30d7 = { 67 a5 [2] 55 87 [2] 53 b2 [2] 7d b2 [2] 42 ae }

  condition:
    any of them
}