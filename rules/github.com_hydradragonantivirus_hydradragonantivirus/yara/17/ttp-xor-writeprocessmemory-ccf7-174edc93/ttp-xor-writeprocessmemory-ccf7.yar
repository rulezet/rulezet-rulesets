rule TTP_XOR_WriteProcessMemory_ccf7 {
  strings:
    $key_ccf7 = { 9b 85 [2] a9 a7 [2] af 92 [2] 81 92 [2] be 8e }

  condition:
    any of them
}