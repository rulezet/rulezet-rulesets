rule TTP_XOR_WriteProcessMemory_808f {
  strings:
    $key_808f = { d7 fd [2] e5 df [2] e3 ea [2] cd ea [2] f2 f6 }

  condition:
    any of them
}