rule TTP_XOR_WriteProcessMemory_89ad {
  strings:
    $key_89ad = { de df [2] ec fd [2] ea c8 [2] c4 c8 [2] fb d4 }

  condition:
    any of them
}