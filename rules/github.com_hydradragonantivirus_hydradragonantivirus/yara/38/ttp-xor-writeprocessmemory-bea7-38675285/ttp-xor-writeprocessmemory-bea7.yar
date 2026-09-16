rule TTP_XOR_WriteProcessMemory_bea7 {
  strings:
    $key_bea7 = { e9 d5 [2] db f7 [2] dd c2 [2] f3 c2 [2] cc de }

  condition:
    any of them
}