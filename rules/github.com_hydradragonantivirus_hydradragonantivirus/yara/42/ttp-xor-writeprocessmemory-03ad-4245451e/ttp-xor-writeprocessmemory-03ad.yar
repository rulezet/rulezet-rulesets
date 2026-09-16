rule TTP_XOR_WriteProcessMemory_03ad {
  strings:
    $key_03ad = { 54 df [2] 66 fd [2] 60 c8 [2] 4e c8 [2] 71 d4 }

  condition:
    any of them
}