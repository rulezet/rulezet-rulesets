rule TTP_XOR_WriteProcessMemory_d5ba {
  strings:
    $key_d5ba = { 82 c8 [2] b0 ea [2] b6 df [2] 98 df [2] a7 c3 }

  condition:
    any of them
}