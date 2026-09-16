rule TTP_XOR_WriteProcessMemory_c3ba {
  strings:
    $key_c3ba = { 94 c8 [2] a6 ea [2] a0 df [2] 8e df [2] b1 c3 }

  condition:
    any of them
}