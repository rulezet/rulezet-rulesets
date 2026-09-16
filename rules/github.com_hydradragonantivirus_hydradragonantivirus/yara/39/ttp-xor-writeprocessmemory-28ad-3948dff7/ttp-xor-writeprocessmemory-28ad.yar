rule TTP_XOR_WriteProcessMemory_28ad {
  strings:
    $key_28ad = { 7f df [2] 4d fd [2] 4b c8 [2] 65 c8 [2] 5a d4 }

  condition:
    any of them
}