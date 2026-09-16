rule TTP_XOR_WriteProcessMemory_1fba {
  strings:
    $key_1fba = { 48 c8 [2] 7a ea [2] 7c df [2] 52 df [2] 6d c3 }

  condition:
    any of them
}