rule TTP_XOR_WriteProcessMemory_cead {
  strings:
    $key_cead = { 99 df [2] ab fd [2] ad c8 [2] 83 c8 [2] bc d4 }

  condition:
    any of them
}