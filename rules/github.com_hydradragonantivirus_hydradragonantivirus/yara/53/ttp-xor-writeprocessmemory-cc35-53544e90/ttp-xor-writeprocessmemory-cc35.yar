rule TTP_XOR_WriteProcessMemory_cc35 {
  strings:
    $key_cc35 = { 9b 47 [2] a9 65 [2] af 50 [2] 81 50 [2] be 4c }

  condition:
    any of them
}