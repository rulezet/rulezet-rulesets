rule TTP_XOR_WriteProcessMemory_73ba {
  strings:
    $key_73ba = { 24 c8 [2] 16 ea [2] 10 df [2] 3e df [2] 01 c3 }

  condition:
    any of them
}