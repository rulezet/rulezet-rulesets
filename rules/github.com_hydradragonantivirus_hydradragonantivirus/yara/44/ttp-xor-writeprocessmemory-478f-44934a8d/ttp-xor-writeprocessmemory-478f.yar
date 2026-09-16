rule TTP_XOR_WriteProcessMemory_478f {
  strings:
    $key_478f = { 10 fd [2] 22 df [2] 24 ea [2] 0a ea [2] 35 f6 }

  condition:
    any of them
}