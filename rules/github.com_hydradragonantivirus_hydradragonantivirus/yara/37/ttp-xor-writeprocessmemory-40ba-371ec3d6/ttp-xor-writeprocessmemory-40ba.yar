rule TTP_XOR_WriteProcessMemory_40ba {
  strings:
    $key_40ba = { 17 c8 [2] 25 ea [2] 23 df [2] 0d df [2] 32 c3 }

  condition:
    any of them
}