rule TTP_XOR_WriteProcessMemory_cc57 {
  strings:
    $key_cc57 = { 9b 25 [2] a9 07 [2] af 32 [2] 81 32 [2] be 2e }

  condition:
    any of them
}