rule TTP_XOR_WriteProcessMemory_40ad {
  strings:
    $key_40ad = { 17 df [2] 25 fd [2] 23 c8 [2] 0d c8 [2] 32 d4 }

  condition:
    any of them
}