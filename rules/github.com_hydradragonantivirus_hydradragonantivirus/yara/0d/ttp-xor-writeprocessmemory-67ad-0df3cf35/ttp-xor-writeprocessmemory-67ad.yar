rule TTP_XOR_WriteProcessMemory_67ad {
  strings:
    $key_67ad = { 30 df [2] 02 fd [2] 04 c8 [2] 2a c8 [2] 15 d4 }

  condition:
    any of them
}