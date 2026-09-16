rule TTP_XOR_WriteProcessMemory_22ba {
  strings:
    $key_22ba = { 75 c8 [2] 47 ea [2] 41 df [2] 6f df [2] 50 c3 }

  condition:
    any of them
}