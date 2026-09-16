rule TTP_XOR_WriteProcessMemory_10c0 {
  strings:
    $key_10c0 = { 47 b2 [2] 75 90 [2] 73 a5 [2] 5d a5 [2] 62 b9 }

  condition:
    any of them
}