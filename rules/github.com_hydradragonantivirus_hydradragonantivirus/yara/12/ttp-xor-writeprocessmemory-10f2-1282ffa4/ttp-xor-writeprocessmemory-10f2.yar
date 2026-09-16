rule TTP_XOR_WriteProcessMemory_10f2 {
  strings:
    $key_10f2 = { 47 80 [2] 75 a2 [2] 73 97 [2] 5d 97 [2] 62 8b }

  condition:
    any of them
}