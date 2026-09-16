rule TTP_XOR_WriteProcessMemory_69c8 {
  strings:
    $key_69c8 = { 3e ba [2] 0c 98 [2] 0a ad [2] 24 ad [2] 1b b1 }

  condition:
    any of them
}