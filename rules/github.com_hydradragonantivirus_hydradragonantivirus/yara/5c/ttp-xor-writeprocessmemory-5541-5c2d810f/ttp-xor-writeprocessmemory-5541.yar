rule TTP_XOR_WriteProcessMemory_5541 {
  strings:
    $key_5541 = { 02 33 [2] 30 11 [2] 36 24 [2] 18 24 [2] 27 38 }

  condition:
    any of them
}