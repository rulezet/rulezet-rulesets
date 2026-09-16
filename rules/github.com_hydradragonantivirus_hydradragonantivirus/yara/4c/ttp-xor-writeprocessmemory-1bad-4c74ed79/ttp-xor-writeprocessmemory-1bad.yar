rule TTP_XOR_WriteProcessMemory_1bad {
  strings:
    $key_1bad = { 4c df [2] 7e fd [2] 78 c8 [2] 56 c8 [2] 69 d4 }

  condition:
    any of them
}