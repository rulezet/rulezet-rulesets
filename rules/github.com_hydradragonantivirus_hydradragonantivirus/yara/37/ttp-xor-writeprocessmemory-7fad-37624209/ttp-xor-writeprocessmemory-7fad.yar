rule TTP_XOR_WriteProcessMemory_7fad {
  strings:
    $key_7fad = { 28 df [2] 1a fd [2] 1c c8 [2] 32 c8 [2] 0d d4 }

  condition:
    any of them
}