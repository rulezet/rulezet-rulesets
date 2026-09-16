rule TTP_XOR_WriteProcessMemory_10d6 {
  strings:
    $key_10d6 = { 47 a4 [2] 75 86 [2] 73 b3 [2] 5d b3 [2] 62 af }

  condition:
    any of them
}