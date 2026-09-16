rule TTP_XOR_WriteProcessMemory_7651 {
  strings:
    $key_7651 = { 21 23 [2] 13 01 [2] 15 34 [2] 3b 34 [2] 04 28 }

  condition:
    any of them
}