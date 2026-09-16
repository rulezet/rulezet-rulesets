rule TTP_XOR_WriteProcessMemory_d4ba {
  strings:
    $key_d4ba = { 83 c8 [2] b1 ea [2] b7 df [2] 99 df [2] a6 c3 }

  condition:
    any of them
}