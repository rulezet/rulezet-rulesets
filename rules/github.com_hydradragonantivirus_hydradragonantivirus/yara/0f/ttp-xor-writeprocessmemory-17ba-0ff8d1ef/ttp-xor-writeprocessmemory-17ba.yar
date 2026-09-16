rule TTP_XOR_WriteProcessMemory_17ba {
  strings:
    $key_17ba = { 40 c8 [2] 72 ea [2] 74 df [2] 5a df [2] 65 c3 }

  condition:
    any of them
}