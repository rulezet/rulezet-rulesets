rule TTP_XOR_WriteProcessMemory_cc65 {
  strings:
    $key_cc65 = { 9b 17 [2] a9 35 [2] af 00 [2] 81 00 [2] be 1c }

  condition:
    any of them
}