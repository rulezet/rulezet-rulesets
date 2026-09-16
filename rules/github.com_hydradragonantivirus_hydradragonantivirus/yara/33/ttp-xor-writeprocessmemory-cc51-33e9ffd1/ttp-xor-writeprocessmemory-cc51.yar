rule TTP_XOR_WriteProcessMemory_cc51 {
  strings:
    $key_cc51 = { 9b 23 [2] a9 01 [2] af 34 [2] 81 34 [2] be 28 }

  condition:
    any of them
}