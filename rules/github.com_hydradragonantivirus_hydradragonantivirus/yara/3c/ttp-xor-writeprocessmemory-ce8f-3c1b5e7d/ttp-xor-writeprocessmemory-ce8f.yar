rule TTP_XOR_WriteProcessMemory_ce8f {
  strings:
    $key_ce8f = { 99 fd [2] ab df [2] ad ea [2] 83 ea [2] bc f6 }

  condition:
    any of them
}