rule TTP_XOR_WriteProcessMemory_63ea {
  strings:
    $key_63ea = { 34 98 [2] 06 ba [2] 00 8f [2] 2e 8f [2] 11 93 }

  condition:
    any of them
}