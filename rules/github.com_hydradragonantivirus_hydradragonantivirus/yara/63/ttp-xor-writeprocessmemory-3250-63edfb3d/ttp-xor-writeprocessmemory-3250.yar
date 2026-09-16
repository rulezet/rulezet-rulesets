rule TTP_XOR_WriteProcessMemory_3250 {
  strings:
    $key_3250 = { 65 22 [2] 57 00 [2] 51 35 [2] 7f 35 [2] 40 29 }

  condition:
    any of them
}