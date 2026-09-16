rule TTP_XOR_WriteProcessMemory_028f {
  strings:
    $key_028f = { 55 fd [2] 67 df [2] 61 ea [2] 4f ea [2] 70 f6 }

  condition:
    any of them
}