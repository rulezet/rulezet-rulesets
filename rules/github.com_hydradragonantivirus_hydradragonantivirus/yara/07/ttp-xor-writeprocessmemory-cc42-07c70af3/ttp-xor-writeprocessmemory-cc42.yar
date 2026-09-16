rule TTP_XOR_WriteProcessMemory_cc42 {
  strings:
    $key_cc42 = { 9b 30 [2] a9 12 [2] af 27 [2] 81 27 [2] be 3b }

  condition:
    any of them
}