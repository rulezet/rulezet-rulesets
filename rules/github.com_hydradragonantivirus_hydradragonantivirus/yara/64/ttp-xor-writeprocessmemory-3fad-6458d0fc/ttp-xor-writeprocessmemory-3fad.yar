rule TTP_XOR_WriteProcessMemory_3fad {
  strings:
    $key_3fad = { 68 df [2] 5a fd [2] 5c c8 [2] 72 c8 [2] 4d d4 }

  condition:
    any of them
}