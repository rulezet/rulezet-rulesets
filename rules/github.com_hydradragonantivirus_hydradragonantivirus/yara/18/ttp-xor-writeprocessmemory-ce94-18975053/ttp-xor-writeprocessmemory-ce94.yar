rule TTP_XOR_WriteProcessMemory_ce94 {
  strings:
    $key_ce94 = { 99 e6 [2] ab c4 [2] ad f1 [2] 83 f1 [2] bc ed }

  condition:
    any of them
}