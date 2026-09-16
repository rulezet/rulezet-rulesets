rule TTP_XOR_WriteProcessMemory_c4ba {
  strings:
    $key_c4ba = { 93 c8 [2] a1 ea [2] a7 df [2] 89 df [2] b6 c3 }

  condition:
    any of them
}