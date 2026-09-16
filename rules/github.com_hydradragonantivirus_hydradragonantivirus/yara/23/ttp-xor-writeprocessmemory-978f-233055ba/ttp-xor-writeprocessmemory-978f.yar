rule TTP_XOR_WriteProcessMemory_978f {
  strings:
    $key_978f = { c0 fd [2] f2 df [2] f4 ea [2] da ea [2] e5 f6 }

  condition:
    any of them
}