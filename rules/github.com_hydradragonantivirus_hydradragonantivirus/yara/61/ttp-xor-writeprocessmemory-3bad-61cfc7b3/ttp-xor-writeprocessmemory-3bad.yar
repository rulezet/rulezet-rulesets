rule TTP_XOR_WriteProcessMemory_3bad {
  strings:
    $key_3bad = { 6c df [2] 5e fd [2] 58 c8 [2] 76 c8 [2] 49 d4 }

  condition:
    any of them
}