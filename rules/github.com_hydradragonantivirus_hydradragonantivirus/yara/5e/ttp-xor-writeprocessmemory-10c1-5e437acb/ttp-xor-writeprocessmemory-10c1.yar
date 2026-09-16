rule TTP_XOR_WriteProcessMemory_10c1 {
  strings:
    $key_10c1 = { 47 b3 [2] 75 91 [2] 73 a4 [2] 5d a4 [2] 62 b8 }

  condition:
    any of them
}