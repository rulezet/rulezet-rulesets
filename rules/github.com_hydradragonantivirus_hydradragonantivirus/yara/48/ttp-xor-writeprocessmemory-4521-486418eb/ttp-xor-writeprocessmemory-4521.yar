rule TTP_XOR_WriteProcessMemory_4521 {
  strings:
    $key_4521 = { 12 53 [2] 20 71 [2] 26 44 [2] 08 44 [2] 37 58 }

  condition:
    any of them
}