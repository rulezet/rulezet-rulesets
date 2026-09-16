rule TTP_XOR_WriteProcessMemory_2fad {
  strings:
    $key_2fad = { 78 df [2] 4a fd [2] 4c c8 [2] 62 c8 [2] 5d d4 }

  condition:
    any of them
}