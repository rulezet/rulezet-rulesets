rule TTP_XOR_WriteProcessMemory_c7ba {
  strings:
    $key_c7ba = { 90 c8 [2] a2 ea [2] a4 df [2] 8a df [2] b5 c3 }

  condition:
    any of them
}