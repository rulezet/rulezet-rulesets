rule TTP_XOR_WriteProcessMemory_c68f {
  strings:
    $key_c68f = { 91 fd [2] a3 df [2] a5 ea [2] 8b ea [2] b4 f6 }

  condition:
    any of them
}