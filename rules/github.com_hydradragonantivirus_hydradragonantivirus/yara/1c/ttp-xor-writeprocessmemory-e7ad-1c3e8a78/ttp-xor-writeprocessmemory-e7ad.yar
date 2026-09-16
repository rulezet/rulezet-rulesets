rule TTP_XOR_WriteProcessMemory_e7ad {
  strings:
    $key_e7ad = { b0 df [2] 82 fd [2] 84 c8 [2] aa c8 [2] 95 d4 }

  condition:
    any of them
}