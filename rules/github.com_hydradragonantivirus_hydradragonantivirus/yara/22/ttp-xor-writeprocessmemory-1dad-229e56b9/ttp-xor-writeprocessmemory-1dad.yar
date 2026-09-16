rule TTP_XOR_WriteProcessMemory_1dad {
  strings:
    $key_1dad = { 4a df [2] 78 fd [2] 7e c8 [2] 50 c8 [2] 6f d4 }

  condition:
    any of them
}