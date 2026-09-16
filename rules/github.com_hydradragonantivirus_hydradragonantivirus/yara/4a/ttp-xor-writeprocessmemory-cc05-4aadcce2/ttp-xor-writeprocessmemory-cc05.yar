rule TTP_XOR_WriteProcessMemory_cc05 {
  strings:
    $key_cc05 = { 9b 77 [2] a9 55 [2] af 60 [2] 81 60 [2] be 7c }

  condition:
    any of them
}