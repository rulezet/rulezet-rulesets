rule TTP_XOR_WriteProcessMemory_13ba {
  strings:
    $key_13ba = { 44 c8 [2] 76 ea [2] 70 df [2] 5e df [2] 61 c3 }

  condition:
    any of them
}