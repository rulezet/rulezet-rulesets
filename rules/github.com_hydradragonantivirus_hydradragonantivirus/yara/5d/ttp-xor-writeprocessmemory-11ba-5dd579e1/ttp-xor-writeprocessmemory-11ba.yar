rule TTP_XOR_WriteProcessMemory_11ba {
  strings:
    $key_11ba = { 46 c8 [2] 74 ea [2] 72 df [2] 5c df [2] 63 c3 }

  condition:
    any of them
}