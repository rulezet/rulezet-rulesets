rule TTP_XOR_WriteProcessMemory_be89 {
  strings:
    $key_be89 = { e9 fb [2] db d9 [2] dd ec [2] f3 ec [2] cc f0 }

  condition:
    any of them
}