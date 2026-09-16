rule TTP_XOR_WriteProcessMemory_4621 {
  strings:
    $key_4621 = { 11 53 [2] 23 71 [2] 25 44 [2] 0b 44 [2] 34 58 }

  condition:
    any of them
}