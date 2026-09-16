rule TTP_XOR_WriteProcessMemory_cc50 {
  strings:
    $key_cc50 = { 9b 22 [2] a9 00 [2] af 35 [2] 81 35 [2] be 29 }

  condition:
    any of them
}