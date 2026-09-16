rule TTP_XOR_WriteProcessMemory_1020 {
  strings:
    $key_1020 = { 47 52 [2] 75 70 [2] 73 45 [2] 5d 45 [2] 62 59 }

  condition:
    any of them
}