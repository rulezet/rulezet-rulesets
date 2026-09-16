rule TTP_XOR_WriteProcessMemory_02ad {
  strings:
    $key_02ad = { 55 df [2] 67 fd [2] 61 c8 [2] 4f c8 [2] 70 d4 }

  condition:
    any of them
}