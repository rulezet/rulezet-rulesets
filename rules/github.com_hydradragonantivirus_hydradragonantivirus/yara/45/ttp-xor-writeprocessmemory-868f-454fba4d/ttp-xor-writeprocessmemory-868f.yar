rule TTP_XOR_WriteProcessMemory_868f {
  strings:
    $key_868f = { d1 fd [2] e3 df [2] e5 ea [2] cb ea [2] f4 f6 }

  condition:
    any of them
}