rule TTP_XOR_WriteProcessMemory_51ba {
  strings:
    $key_51ba = { 06 c8 [2] 34 ea [2] 32 df [2] 1c df [2] 23 c3 }

  condition:
    any of them
}