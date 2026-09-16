rule TTP_XOR_WriteProcessMemory_ccbe {
  strings:
    $key_ccbe = { 9b cc [2] a9 ee [2] af db [2] 81 db [2] be c7 }

  condition:
    any of them
}