rule TTP_XOR_WriteProcessMemory_5471 {
  strings:
    $key_5471 = { 03 03 [2] 31 21 [2] 37 14 [2] 19 14 [2] 26 08 }

  condition:
    any of them
}