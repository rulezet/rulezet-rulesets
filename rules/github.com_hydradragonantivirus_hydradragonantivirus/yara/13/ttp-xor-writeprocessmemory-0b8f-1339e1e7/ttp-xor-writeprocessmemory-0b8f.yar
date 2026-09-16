rule TTP_XOR_WriteProcessMemory_0b8f {
  strings:
    $key_0b8f = { 5c fd [2] 6e df [2] 68 ea [2] 46 ea [2] 79 f6 }

  condition:
    any of them
}