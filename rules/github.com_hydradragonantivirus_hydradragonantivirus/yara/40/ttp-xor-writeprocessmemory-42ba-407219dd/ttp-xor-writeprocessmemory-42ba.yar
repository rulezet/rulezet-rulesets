rule TTP_XOR_WriteProcessMemory_42ba {
  strings:
    $key_42ba = { 15 c8 [2] 27 ea [2] 21 df [2] 0f df [2] 30 c3 }

  condition:
    any of them
}