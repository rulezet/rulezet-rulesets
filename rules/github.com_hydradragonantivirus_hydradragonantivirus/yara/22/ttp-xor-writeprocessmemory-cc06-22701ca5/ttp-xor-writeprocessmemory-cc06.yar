rule TTP_XOR_WriteProcessMemory_cc06 {
  strings:
    $key_cc06 = { 9b 74 [2] a9 56 [2] af 63 [2] 81 63 [2] be 7f }

  condition:
    any of them
}