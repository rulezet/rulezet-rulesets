rule TTP_XOR_WriteProcessMemory_cdbe {
  strings:
    $key_cdbe = { 9a cc [2] a8 ee [2] ae db [2] 80 db [2] bf c7 }

  condition:
    any of them
}