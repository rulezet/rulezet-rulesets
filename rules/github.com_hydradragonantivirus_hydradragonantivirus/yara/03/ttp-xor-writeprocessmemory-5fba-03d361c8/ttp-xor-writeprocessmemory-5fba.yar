rule TTP_XOR_WriteProcessMemory_5fba {
  strings:
    $key_5fba = { 08 c8 [2] 3a ea [2] 3c df [2] 12 df [2] 2d c3 }

  condition:
    any of them
}