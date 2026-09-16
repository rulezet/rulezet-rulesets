rule TTP_XOR_WriteProcessMemory_9f8f {
  strings:
    $key_9f8f = { c8 fd [2] fa df [2] fc ea [2] d2 ea [2] ed f6 }

  condition:
    any of them
}