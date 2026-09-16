rule TTP_XOR_WriteProcessMemory_19c8 {
  strings:
    $key_19c8 = { 4e ba [2] 7c 98 [2] 7a ad [2] 54 ad [2] 6b b1 }

  condition:
    any of them
}