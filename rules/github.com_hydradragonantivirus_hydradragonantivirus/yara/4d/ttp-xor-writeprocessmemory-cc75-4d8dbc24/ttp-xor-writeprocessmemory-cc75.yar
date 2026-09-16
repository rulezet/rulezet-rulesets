rule TTP_XOR_WriteProcessMemory_cc75 {
  strings:
    $key_cc75 = { 9b 07 [2] a9 25 [2] af 10 [2] 81 10 [2] be 0c }

  condition:
    any of them
}