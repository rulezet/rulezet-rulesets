rule TTP_XOR_WriteProcessMemory_2860 {
  strings:
    $key_2860 = { 7f 12 [2] 4d 30 [2] 4b 05 [2] 65 05 [2] 5a 19 }

  condition:
    any of them
}