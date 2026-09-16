rule TTP_XOR_WriteProcessMemory_d48f {
  strings:
    $key_d48f = { 83 fd [2] b1 df [2] b7 ea [2] 99 ea [2] a6 f6 }

  condition:
    any of them
}