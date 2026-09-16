rule TTP_XOR_WriteProcessMemory_7a8f {
  strings:
    $key_7a8f = { 2d fd [2] 1f df [2] 19 ea [2] 37 ea [2] 08 f6 }

  condition:
    any of them
}