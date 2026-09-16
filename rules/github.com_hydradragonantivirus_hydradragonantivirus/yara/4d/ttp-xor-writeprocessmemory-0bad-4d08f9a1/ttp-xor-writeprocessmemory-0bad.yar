rule TTP_XOR_WriteProcessMemory_0bad {
  strings:
    $key_0bad = { 5c df [2] 6e fd [2] 68 c8 [2] 46 c8 [2] 79 d4 }

  condition:
    any of them
}