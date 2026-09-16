rule TTP_XOR_WriteProcessMemory_91ba {
  strings:
    $key_91ba = { c6 c8 [2] f4 ea [2] f2 df [2] dc df [2] e3 c3 }

  condition:
    any of them
}