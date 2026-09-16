rule TTP_XOR_WriteProcessMemory_c098 {
  strings:
    $key_c098 = { 97 ea [2] a5 c8 [2] a3 fd [2] 8d fd [2] b2 e1 }

  condition:
    any of them
}