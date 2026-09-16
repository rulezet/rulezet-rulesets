rule TTP_XOR_WriteProcessMemory_3fba {
  strings:
    $key_3fba = { 68 c8 [2] 5a ea [2] 5c df [2] 72 df [2] 4d c3 }

  condition:
    any of them
}