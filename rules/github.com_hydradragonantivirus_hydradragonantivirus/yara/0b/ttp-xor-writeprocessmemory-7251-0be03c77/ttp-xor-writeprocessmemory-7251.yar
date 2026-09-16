rule TTP_XOR_WriteProcessMemory_7251 {
  strings:
    $key_7251 = { 25 23 [2] 17 01 [2] 11 34 [2] 3f 34 [2] 00 28 }

  condition:
    any of them
}