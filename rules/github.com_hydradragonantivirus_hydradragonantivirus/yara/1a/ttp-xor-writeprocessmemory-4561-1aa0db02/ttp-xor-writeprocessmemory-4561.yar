rule TTP_XOR_WriteProcessMemory_4561 {
  strings:
    $key_4561 = { 12 13 [2] 20 31 [2] 26 04 [2] 08 04 [2] 37 18 }

  condition:
    any of them
}