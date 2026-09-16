rule TTP_XOR_WriteProcessMemory_ccf1 {
  strings:
    $key_ccf1 = { 9b 83 [2] a9 a1 [2] af 94 [2] 81 94 [2] be 88 }

  condition:
    any of them
}