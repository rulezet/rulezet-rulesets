rule TTP_XOR_WriteProcessMemory_cc56 {
  strings:
    $key_cc56 = { 9b 24 [2] a9 06 [2] af 33 [2] 81 33 [2] be 2f }

  condition:
    any of them
}