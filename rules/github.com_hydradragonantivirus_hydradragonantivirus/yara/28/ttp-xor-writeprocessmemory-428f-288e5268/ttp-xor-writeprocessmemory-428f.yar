rule TTP_XOR_WriteProcessMemory_428f {
  strings:
    $key_428f = { 15 fd [2] 27 df [2] 21 ea [2] 0f ea [2] 30 f6 }

  condition:
    any of them
}