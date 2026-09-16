rule TTP_XOR_WriteProcessMemory_48ad {
  strings:
    $key_48ad = { 1f df [2] 2d fd [2] 2b c8 [2] 05 c8 [2] 3a d4 }

  condition:
    any of them
}