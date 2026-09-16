rule TTP_XOR_WriteProcessMemory_bbac {
  strings:
    $key_bbac = { ec de [2] de fc [2] d8 c9 [2] f6 c9 [2] c9 d5 }

  condition:
    any of them
}