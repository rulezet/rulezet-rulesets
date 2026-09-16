rule TTP_XOR_WriteProcessMemory_72ba {
  strings:
    $key_72ba = { 25 c8 [2] 17 ea [2] 11 df [2] 3f df [2] 00 c3 }

  condition:
    any of them
}