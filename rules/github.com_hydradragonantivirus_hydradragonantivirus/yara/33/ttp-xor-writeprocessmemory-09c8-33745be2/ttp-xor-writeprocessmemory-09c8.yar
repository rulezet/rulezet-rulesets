rule TTP_XOR_WriteProcessMemory_09c8 {
  strings:
    $key_09c8 = { 5e ba [2] 6c 98 [2] 6a ad [2] 44 ad [2] 7b b1 }

  condition:
    any of them
}