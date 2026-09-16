rule TTP_XOR_WriteProcessMemory_e8c8 {
  strings:
    $key_e8c8 = { bf ba [2] 8d 98 [2] 8b ad [2] a5 ad [2] 9a b1 }

  condition:
    any of them
}