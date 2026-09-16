rule TTP_XOR_WriteProcessMemory_10c7 {
  strings:
    $key_10c7 = { 47 b5 [2] 75 97 [2] 73 a2 [2] 5d a2 [2] 62 be }

  condition:
    any of them
}