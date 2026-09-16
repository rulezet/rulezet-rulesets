rule TTP_XOR_WriteProcessMemory_c9ac {
  strings:
    $key_c9ac = { 9e de [2] ac fc [2] aa c9 [2] 84 c9 [2] bb d5 }

  condition:
    any of them
}