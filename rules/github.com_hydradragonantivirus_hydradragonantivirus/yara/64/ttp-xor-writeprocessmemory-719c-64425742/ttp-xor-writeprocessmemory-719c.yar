rule TTP_XOR_WriteProcessMemory_719c {
  strings:
    $key_719c = { 26 ee [2] 14 cc [2] 12 f9 [2] 3c f9 [2] 03 e5 }

  condition:
    any of them
}