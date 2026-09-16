rule TTP_XOR_WriteProcessMemory_ffad {
  strings:
    $key_ffad = { a8 df [2] 9a fd [2] 9c c8 [2] b2 c8 [2] 8d d4 }

  condition:
    any of them
}