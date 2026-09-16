rule TTP_XOR_WriteProcessMemory_cc86 {
  strings:
    $key_cc86 = { 9b f4 [2] a9 d6 [2] af e3 [2] 81 e3 [2] be ff }

  condition:
    any of them
}