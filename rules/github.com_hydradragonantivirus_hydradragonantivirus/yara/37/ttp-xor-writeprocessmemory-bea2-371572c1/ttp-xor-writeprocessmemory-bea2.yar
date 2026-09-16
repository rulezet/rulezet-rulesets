rule TTP_XOR_WriteProcessMemory_bea2 {
  strings:
    $key_bea2 = { e9 d0 [2] db f2 [2] dd c7 [2] f3 c7 [2] cc db }

  condition:
    any of them
}