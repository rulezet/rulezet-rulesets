rule TTP_XOR_WriteProcessMemory_0fba {
  strings:
    $key_0fba = { 58 c8 [2] 6a ea [2] 6c df [2] 42 df [2] 7d c3 }

  condition:
    any of them
}