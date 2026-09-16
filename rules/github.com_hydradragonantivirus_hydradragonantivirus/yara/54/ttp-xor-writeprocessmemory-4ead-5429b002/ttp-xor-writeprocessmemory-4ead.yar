rule TTP_XOR_WriteProcessMemory_4ead {
  strings:
    $key_4ead = { 19 df [2] 2b fd [2] 2d c8 [2] 03 c8 [2] 3c d4 }

  condition:
    any of them
}