rule TTP_XOR_WriteProcessMemory_eead {
  strings:
    $key_eead = { b9 df [2] 8b fd [2] 8d c8 [2] a3 c8 [2] 9c d4 }

  condition:
    any of them
}