rule TTP_XOR_WriteProcessMemory_c2ba {
  strings:
    $key_c2ba = { 95 c8 [2] a7 ea [2] a1 df [2] 8f df [2] b0 c3 }

  condition:
    any of them
}