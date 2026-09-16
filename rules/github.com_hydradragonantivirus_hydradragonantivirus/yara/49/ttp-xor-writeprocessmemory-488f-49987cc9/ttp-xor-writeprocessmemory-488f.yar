rule TTP_XOR_WriteProcessMemory_488f {
  strings:
    $key_488f = { 1f fd [2] 2d df [2] 2b ea [2] 05 ea [2] 3a f6 }

  condition:
    any of them
}