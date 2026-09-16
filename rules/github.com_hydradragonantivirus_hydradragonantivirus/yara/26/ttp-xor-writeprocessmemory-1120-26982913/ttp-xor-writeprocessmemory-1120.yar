rule TTP_XOR_WriteProcessMemory_1120 {
  strings:
    $key_1120 = { 46 52 [2] 74 70 [2] 72 45 [2] 5c 45 [2] 63 59 }

  condition:
    any of them
}