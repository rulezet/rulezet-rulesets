rule TTP_XOR_WriteProcessMemory_678f {
  strings:
    $key_678f = { 30 fd [2] 02 df [2] 04 ea [2] 2a ea [2] 15 f6 }

  condition:
    any of them
}