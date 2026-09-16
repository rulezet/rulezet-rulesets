rule TTP_XOR_WriteProcessMemory_45ba {
  strings:
    $key_45ba = { 12 c8 [2] 20 ea [2] 26 df [2] 08 df [2] 37 c3 }

  condition:
    any of them
}