rule TTP_XOR_WriteProcessMemory_97ba {
  strings:
    $key_97ba = { c0 c8 [2] f2 ea [2] f4 df [2] da df [2] e5 c3 }

  condition:
    any of them
}