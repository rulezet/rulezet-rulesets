rule TTP_XOR_WriteProcessMemory_bd8f {
  strings:
    $key_bd8f = { ea fd [2] d8 df [2] de ea [2] f0 ea [2] cf f6 }

  condition:
    any of them
}