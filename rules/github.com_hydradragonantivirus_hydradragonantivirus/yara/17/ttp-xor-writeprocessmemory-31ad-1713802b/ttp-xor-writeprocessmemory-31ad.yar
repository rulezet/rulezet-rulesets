rule TTP_XOR_WriteProcessMemory_31ad {
  strings:
    $key_31ad = { 66 df [2] 54 fd [2] 52 c8 [2] 7c c8 [2] 43 d4 }

  condition:
    any of them
}