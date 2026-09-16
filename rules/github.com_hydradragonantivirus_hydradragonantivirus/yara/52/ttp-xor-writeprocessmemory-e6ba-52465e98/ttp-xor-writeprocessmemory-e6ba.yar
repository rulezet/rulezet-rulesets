rule TTP_XOR_WriteProcessMemory_e6ba {
  strings:
    $key_e6ba = { b1 c8 [2] 83 ea [2] 85 df [2] ab df [2] 94 c3 }

  condition:
    any of them
}