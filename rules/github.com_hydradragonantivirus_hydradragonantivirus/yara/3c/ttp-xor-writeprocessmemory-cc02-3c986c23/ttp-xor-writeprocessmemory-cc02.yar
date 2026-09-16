rule TTP_XOR_WriteProcessMemory_cc02 {
  strings:
    $key_cc02 = { 9b 70 [2] a9 52 [2] af 67 [2] 81 67 [2] be 7b }

  condition:
    any of them
}