rule TTP_XOR_WriteProcessMemory_7ead {
  strings:
    $key_7ead = { 29 df [2] 1b fd [2] 1d c8 [2] 33 c8 [2] 0c d4 }

  condition:
    any of them
}