rule TTP_XOR_WriteProcessMemory_30ad {
  strings:
    $key_30ad = { 67 df [2] 55 fd [2] 53 c8 [2] 7d c8 [2] 42 d4 }

  condition:
    any of them
}