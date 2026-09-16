rule TTP_XOR_WriteProcessMemory_5ead {
  strings:
    $key_5ead = { 09 df [2] 3b fd [2] 3d c8 [2] 13 c8 [2] 2c d4 }

  condition:
    any of them
}