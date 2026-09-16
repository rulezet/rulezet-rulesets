rule TTP_XOR_WriteProcessMemory_d798 {
  strings:
    $key_d798 = { 80 ea [2] b2 c8 [2] b4 fd [2] 9a fd [2] a5 e1 }

  condition:
    any of them
}