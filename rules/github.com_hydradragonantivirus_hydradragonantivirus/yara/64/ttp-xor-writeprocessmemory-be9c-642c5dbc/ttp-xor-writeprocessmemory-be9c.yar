rule TTP_XOR_WriteProcessMemory_be9c {
  strings:
    $key_be9c = { e9 ee [2] db cc [2] dd f9 [2] f3 f9 [2] cc e5 }

  condition:
    any of them
}