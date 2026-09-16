rule TTP_XOR_WriteProcessMemory_e0ad {
  strings:
    $key_e0ad = { b7 df [2] 85 fd [2] 83 c8 [2] ad c8 [2] 92 d4 }

  condition:
    any of them
}