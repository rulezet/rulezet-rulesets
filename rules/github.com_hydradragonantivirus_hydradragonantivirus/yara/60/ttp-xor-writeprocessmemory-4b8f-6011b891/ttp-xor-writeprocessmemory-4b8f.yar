rule TTP_XOR_WriteProcessMemory_4b8f {
  strings:
    $key_4b8f = { 1c fd [2] 2e df [2] 28 ea [2] 06 ea [2] 39 f6 }

  condition:
    any of them
}