rule TTP_XOR_WriteProcessMemory_faad {
  strings:
    $key_faad = { ad df [2] 9f fd [2] 99 c8 [2] b7 c8 [2] 88 d4 }

  condition:
    any of them
}