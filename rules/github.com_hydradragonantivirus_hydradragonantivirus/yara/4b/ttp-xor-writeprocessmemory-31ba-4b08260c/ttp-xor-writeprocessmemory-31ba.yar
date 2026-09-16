rule TTP_XOR_WriteProcessMemory_31ba {
  strings:
    $key_31ba = { 66 c8 [2] 54 ea [2] 52 df [2] 7c df [2] 43 c3 }

  condition:
    any of them
}