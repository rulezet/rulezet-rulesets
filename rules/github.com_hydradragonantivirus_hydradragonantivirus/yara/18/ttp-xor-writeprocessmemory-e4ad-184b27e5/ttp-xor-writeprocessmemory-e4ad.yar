rule TTP_XOR_WriteProcessMemory_e4ad {
  strings:
    $key_e4ad = { b3 df [2] 81 fd [2] 87 c8 [2] a9 c8 [2] 96 d4 }

  condition:
    any of them
}