rule TTP_XOR_WriteProcessMemory_8d8f {
  strings:
    $key_8d8f = { da fd [2] e8 df [2] ee ea [2] c0 ea [2] ff f6 }

  condition:
    any of them
}