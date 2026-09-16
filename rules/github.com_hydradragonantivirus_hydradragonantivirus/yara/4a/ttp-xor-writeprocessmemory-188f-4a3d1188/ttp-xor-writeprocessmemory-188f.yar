rule TTP_XOR_WriteProcessMemory_188f {
  strings:
    $key_188f = { 4f fd [2] 7d df [2] 7b ea [2] 55 ea [2] 6a f6 }

  condition:
    any of them
}