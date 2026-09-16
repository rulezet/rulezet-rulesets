rule TTP_XOR_WriteProcessMemory_01ba {
  strings:
    $key_01ba = { 56 c8 [2] 64 ea [2] 62 df [2] 4c df [2] 73 c3 }

  condition:
    any of them
}