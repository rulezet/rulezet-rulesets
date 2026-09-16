rule TTP_XOR_WriteProcessMemory_ac8f {
  strings:
    $key_ac8f = { fb fd [2] c9 df [2] cf ea [2] e1 ea [2] de f6 }

  condition:
    any of them
}