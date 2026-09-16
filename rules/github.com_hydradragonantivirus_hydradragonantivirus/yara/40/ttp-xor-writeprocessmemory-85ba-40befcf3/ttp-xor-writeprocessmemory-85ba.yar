rule TTP_XOR_WriteProcessMemory_85ba {
  strings:
    $key_85ba = { d2 c8 [2] e0 ea [2] e6 df [2] c8 df [2] f7 c3 }

  condition:
    any of them
}