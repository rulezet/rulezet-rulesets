rule TTP_XOR_WriteProcessMemory_118f {
  strings:
    $key_118f = { 46 fd [2] 74 df [2] 72 ea [2] 5c ea [2] 63 f6 }

  condition:
    any of them
}