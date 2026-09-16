rule TTP_XOR_WriteProcessMemory_8e8f {
  strings:
    $key_8e8f = { d9 fd [2] eb df [2] ed ea [2] c3 ea [2] fc f6 }

  condition:
    any of them
}