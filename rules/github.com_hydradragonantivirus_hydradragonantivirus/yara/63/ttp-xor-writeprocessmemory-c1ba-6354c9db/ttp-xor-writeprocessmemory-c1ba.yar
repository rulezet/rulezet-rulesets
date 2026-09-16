rule TTP_XOR_WriteProcessMemory_c1ba {
  strings:
    $key_c1ba = { 96 c8 [2] a4 ea [2] a2 df [2] 8c df [2] b3 c3 }

  condition:
    any of them
}