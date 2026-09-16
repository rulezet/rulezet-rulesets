rule TTP_XOR_WriteProcessMemory_dea2 {
  strings:
    $key_dea2 = { 89 d0 [2] bb f2 [2] bd c7 [2] 93 c7 [2] ac db }

  condition:
    any of them
}