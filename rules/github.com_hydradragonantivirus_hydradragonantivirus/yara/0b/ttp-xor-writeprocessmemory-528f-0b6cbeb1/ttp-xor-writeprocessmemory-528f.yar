rule TTP_XOR_WriteProcessMemory_528f {
  strings:
    $key_528f = { 05 fd [2] 37 df [2] 31 ea [2] 1f ea [2] 20 f6 }

  condition:
    any of them
}