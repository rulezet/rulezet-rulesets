rule TTP_XOR_WriteProcessMemory_c9ea {
  strings:
    $key_c9ea = { 9e 98 [2] ac ba [2] aa 8f [2] 84 8f [2] bb 93 }

  condition:
    any of them
}