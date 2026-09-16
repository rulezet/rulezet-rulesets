rule TTP_XOR_WriteProcessMemory_10d0 {
  strings:
    $key_10d0 = { 47 a2 [2] 75 80 [2] 73 b5 [2] 5d b5 [2] 62 a9 }

  condition:
    any of them
}