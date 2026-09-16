rule TTP_XOR_WriteProcessMemory_e7ba {
  strings:
    $key_e7ba = { b0 c8 [2] 82 ea [2] 84 df [2] aa df [2] 95 c3 }

  condition:
    any of them
}