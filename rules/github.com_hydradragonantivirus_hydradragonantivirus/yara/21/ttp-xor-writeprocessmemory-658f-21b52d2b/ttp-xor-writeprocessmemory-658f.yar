rule TTP_XOR_WriteProcessMemory_658f {
  strings:
    $key_658f = { 32 fd [2] 00 df [2] 06 ea [2] 28 ea [2] 17 f6 }

  condition:
    any of them
}