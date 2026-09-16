rule TTP_XOR_WriteProcessMemory_1720 {
  strings:
    $key_1720 = { 40 52 [2] 72 70 [2] 74 45 [2] 5a 45 [2] 65 59 }

  condition:
    any of them
}