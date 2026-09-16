rule TTP_XOR_WriteProcessMemory_e98f {
  strings:
    $key_e98f = { be fd [2] 8c df [2] 8a ea [2] a4 ea [2] 9b f6 }

  condition:
    any of them
}