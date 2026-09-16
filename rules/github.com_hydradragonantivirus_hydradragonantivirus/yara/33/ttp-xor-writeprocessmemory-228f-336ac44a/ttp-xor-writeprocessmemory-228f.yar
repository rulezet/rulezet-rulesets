rule TTP_XOR_WriteProcessMemory_228f {
  strings:
    $key_228f = { 75 fd [2] 47 df [2] 41 ea [2] 6f ea [2] 50 f6 }

  condition:
    any of them
}