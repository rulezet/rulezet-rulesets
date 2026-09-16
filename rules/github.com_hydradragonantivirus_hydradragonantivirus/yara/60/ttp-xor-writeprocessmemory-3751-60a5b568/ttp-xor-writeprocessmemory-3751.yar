rule TTP_XOR_WriteProcessMemory_3751 {
  strings:
    $key_3751 = { 60 23 [2] 52 01 [2] 54 34 [2] 7a 34 [2] 45 28 }

  condition:
    any of them
}