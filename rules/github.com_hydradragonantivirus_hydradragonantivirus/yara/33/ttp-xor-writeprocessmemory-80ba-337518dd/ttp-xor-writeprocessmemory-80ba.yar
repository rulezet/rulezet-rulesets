rule TTP_XOR_WriteProcessMemory_80ba {
  strings:
    $key_80ba = { d7 c8 [2] e5 ea [2] e3 df [2] cd df [2] f2 c3 }

  condition:
    any of them
}