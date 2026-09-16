rule TTP_XOR_WriteProcessMemory_3251 {
  strings:
    $key_3251 = { 65 23 [2] 57 01 [2] 51 34 [2] 7f 34 [2] 40 28 }

  condition:
    any of them
}