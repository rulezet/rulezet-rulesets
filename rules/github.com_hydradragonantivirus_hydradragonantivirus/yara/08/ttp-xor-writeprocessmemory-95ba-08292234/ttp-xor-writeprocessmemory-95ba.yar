rule TTP_XOR_WriteProcessMemory_95ba {
  strings:
    $key_95ba = { c2 c8 [2] f0 ea [2] f6 df [2] d8 df [2] e7 c3 }

  condition:
    any of them
}