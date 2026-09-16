rule TTP_XOR_WriteProcessMemory_1042 {
  strings:
    $key_1042 = { 47 30 [2] 75 12 [2] 73 27 [2] 5d 27 [2] 62 3b }

  condition:
    any of them
}