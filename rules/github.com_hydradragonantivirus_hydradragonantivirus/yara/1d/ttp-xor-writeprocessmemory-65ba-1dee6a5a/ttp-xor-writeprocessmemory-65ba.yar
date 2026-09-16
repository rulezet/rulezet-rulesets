rule TTP_XOR_WriteProcessMemory_65ba {
  strings:
    $key_65ba = { 32 c8 [2] 00 ea [2] 06 df [2] 28 df [2] 17 c3 }

  condition:
    any of them
}