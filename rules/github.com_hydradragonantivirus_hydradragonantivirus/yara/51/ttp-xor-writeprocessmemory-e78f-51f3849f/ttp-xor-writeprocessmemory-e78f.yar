rule TTP_XOR_WriteProcessMemory_e78f {
  strings:
    $key_e78f = { b0 fd [2] 82 df [2] 84 ea [2] aa ea [2] 95 f6 }

  condition:
    any of them
}