rule TTP_XOR_WriteProcessMemory_6fba {
  strings:
    $key_6fba = { 38 c8 [2] 0a ea [2] 0c df [2] 22 df [2] 1d c3 }

  condition:
    any of them
}