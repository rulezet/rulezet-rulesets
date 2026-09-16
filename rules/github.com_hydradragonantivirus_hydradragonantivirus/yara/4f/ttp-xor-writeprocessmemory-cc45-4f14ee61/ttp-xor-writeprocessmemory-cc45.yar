rule TTP_XOR_WriteProcessMemory_cc45 {
  strings:
    $key_cc45 = { 9b 37 [2] a9 15 [2] af 20 [2] 81 20 [2] be 3c }

  condition:
    any of them
}