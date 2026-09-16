rule TTP_XOR_WriteProcessMemory_5020 {
  strings:
    $key_5020 = { 07 52 [2] 35 70 [2] 33 45 [2] 1d 45 [2] 22 59 }

  condition:
    any of them
}