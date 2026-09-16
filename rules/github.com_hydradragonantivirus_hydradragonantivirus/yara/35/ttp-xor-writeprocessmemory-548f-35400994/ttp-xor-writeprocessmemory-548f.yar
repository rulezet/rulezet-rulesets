rule TTP_XOR_WriteProcessMemory_548f {
  strings:
    $key_548f = { 03 fd [2] 31 df [2] 37 ea [2] 19 ea [2] 26 f6 }

  condition:
    any of them
}