rule TTP_XOR_WriteProcessMemory_048f {
  strings:
    $key_048f = { 53 fd [2] 61 df [2] 67 ea [2] 49 ea [2] 76 f6 }

  condition:
    any of them
}