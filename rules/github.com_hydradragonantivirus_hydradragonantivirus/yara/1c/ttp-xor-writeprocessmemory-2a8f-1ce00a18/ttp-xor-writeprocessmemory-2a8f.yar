rule TTP_XOR_WriteProcessMemory_2a8f {
  strings:
    $key_2a8f = { 7d fd [2] 4f df [2] 49 ea [2] 67 ea [2] 58 f6 }

  condition:
    any of them
}