rule TTP_XOR_WriteProcessMemory_2650 {
  strings:
    $key_2650 = { 71 22 [2] 43 00 [2] 45 35 [2] 6b 35 [2] 54 29 }

  condition:
    any of them
}