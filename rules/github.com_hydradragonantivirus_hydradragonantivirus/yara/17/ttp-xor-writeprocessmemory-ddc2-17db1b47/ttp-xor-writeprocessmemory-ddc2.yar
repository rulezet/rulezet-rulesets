rule TTP_XOR_WriteProcessMemory_ddc2 {
  strings:
    $key_ddc2 = { 8a b0 [2] b8 92 [2] be a7 [2] 90 a7 [2] af bb }

  condition:
    any of them
}