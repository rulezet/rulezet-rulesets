rule TTP_XOR_WriteProcessMemory_cf8f {
  strings:
    $key_cf8f = { 98 fd [2] aa df [2] ac ea [2] 82 ea [2] bd f6 }

  condition:
    any of them
}