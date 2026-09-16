rule TTP_XOR_WriteProcessMemory_ceca {
  strings:
    $key_ceca = { 99 b8 [2] ab 9a [2] ad af [2] 83 af [2] bc b3 }

  condition:
    any of them
}