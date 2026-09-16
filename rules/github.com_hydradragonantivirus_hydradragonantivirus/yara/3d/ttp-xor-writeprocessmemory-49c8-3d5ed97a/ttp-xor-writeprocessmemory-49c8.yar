rule TTP_XOR_WriteProcessMemory_49c8 {
  strings:
    $key_49c8 = { 1e ba [2] 2c 98 [2] 2a ad [2] 04 ad [2] 3b b1 }

  condition:
    any of them
}