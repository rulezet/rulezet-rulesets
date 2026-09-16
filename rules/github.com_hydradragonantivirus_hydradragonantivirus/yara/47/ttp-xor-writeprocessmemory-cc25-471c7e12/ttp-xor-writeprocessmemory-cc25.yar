rule TTP_XOR_WriteProcessMemory_cc25 {
  strings:
    $key_cc25 = { 9b 57 [2] a9 75 [2] af 40 [2] 81 40 [2] be 5c }

  condition:
    any of them
}