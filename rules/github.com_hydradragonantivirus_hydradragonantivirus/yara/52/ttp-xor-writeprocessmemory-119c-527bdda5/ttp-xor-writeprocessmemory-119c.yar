rule TTP_XOR_WriteProcessMemory_119c {
  strings:
    $key_119c = { 46 ee [2] 74 cc [2] 72 f9 [2] 5c f9 [2] 63 e5 }

  condition:
    any of them
}