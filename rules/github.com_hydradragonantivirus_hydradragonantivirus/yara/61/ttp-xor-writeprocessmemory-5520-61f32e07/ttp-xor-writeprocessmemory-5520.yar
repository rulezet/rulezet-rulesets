rule TTP_XOR_WriteProcessMemory_5520 {
  strings:
    $key_5520 = { 02 52 [2] 30 70 [2] 36 45 [2] 18 45 [2] 27 59 }

  condition:
    any of them
}