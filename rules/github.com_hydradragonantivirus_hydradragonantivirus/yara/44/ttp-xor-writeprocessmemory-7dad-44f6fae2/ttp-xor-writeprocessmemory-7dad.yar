rule TTP_XOR_WriteProcessMemory_7dad {
  strings:
    $key_7dad = { 2a df [2] 18 fd [2] 1e c8 [2] 30 c8 [2] 0f d4 }

  condition:
    any of them
}