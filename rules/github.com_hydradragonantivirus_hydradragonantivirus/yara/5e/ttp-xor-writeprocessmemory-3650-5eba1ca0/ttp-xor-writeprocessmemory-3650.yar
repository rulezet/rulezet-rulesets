rule TTP_XOR_WriteProcessMemory_3650 {
  strings:
    $key_3650 = { 61 22 [2] 53 00 [2] 55 35 [2] 7b 35 [2] 44 29 }

  condition:
    any of them
}