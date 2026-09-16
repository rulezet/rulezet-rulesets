rule TTP_XOR_WriteProcessMemory_08ad {
  strings:
    $key_08ad = { 5f df [2] 6d fd [2] 6b c8 [2] 45 c8 [2] 7a d4 }

  condition:
    any of them
}