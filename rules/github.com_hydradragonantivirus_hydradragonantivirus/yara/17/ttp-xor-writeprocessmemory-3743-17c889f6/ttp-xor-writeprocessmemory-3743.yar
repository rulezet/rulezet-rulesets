rule TTP_XOR_WriteProcessMemory_3743 {
  strings:
    $key_3743 = { 60 31 [2] 52 13 [2] 54 26 [2] 7a 26 [2] 45 3a }

  condition:
    any of them
}