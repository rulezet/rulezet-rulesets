rule TTP_XOR_WriteProcessMemory_efba {
  strings:
    $key_efba = { b8 c8 [2] 8a ea [2] 8c df [2] a2 df [2] 9d c3 }

  condition:
    any of them
}