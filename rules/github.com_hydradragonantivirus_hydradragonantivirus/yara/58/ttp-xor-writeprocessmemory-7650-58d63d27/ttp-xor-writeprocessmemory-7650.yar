rule TTP_XOR_WriteProcessMemory_7650 {
  strings:
    $key_7650 = { 21 22 [2] 13 00 [2] 15 35 [2] 3b 35 [2] 04 29 }

  condition:
    any of them
}