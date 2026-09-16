rule TTP_XOR_WriteProcessMemory_4550 {
  strings:
    $key_4550 = { 12 22 [2] 20 00 [2] 26 35 [2] 08 35 [2] 37 29 }

  condition:
    any of them
}