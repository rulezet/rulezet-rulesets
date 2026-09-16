rule TTP_XOR_WriteProcessMemory_2ead {
  strings:
    $key_2ead = { 79 df [2] 4b fd [2] 4d c8 [2] 63 c8 [2] 5c d4 }

  condition:
    any of them
}