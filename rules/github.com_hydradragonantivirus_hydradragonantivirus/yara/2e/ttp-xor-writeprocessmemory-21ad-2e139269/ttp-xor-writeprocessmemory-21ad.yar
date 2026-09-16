rule TTP_XOR_WriteProcessMemory_21ad {
  strings:
    $key_21ad = { 76 df [2] 44 fd [2] 42 c8 [2] 6c c8 [2] 53 d4 }

  condition:
    any of them
}