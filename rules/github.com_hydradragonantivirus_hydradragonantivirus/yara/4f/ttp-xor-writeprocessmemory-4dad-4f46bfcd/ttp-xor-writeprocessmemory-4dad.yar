rule TTP_XOR_WriteProcessMemory_4dad {
  strings:
    $key_4dad = { 1a df [2] 28 fd [2] 2e c8 [2] 00 c8 [2] 3f d4 }

  condition:
    any of them
}