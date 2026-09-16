rule TTP_XOR_WriteProcessMemory_5b8f {
  strings:
    $key_5b8f = { 0c fd [2] 3e df [2] 38 ea [2] 16 ea [2] 29 f6 }

  condition:
    any of them
}