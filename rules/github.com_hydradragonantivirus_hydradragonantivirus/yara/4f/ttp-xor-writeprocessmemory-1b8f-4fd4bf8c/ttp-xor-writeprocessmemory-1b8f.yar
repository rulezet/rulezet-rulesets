rule TTP_XOR_WriteProcessMemory_1b8f {
  strings:
    $key_1b8f = { 4c fd [2] 7e df [2] 78 ea [2] 56 ea [2] 69 f6 }

  condition:
    any of them
}