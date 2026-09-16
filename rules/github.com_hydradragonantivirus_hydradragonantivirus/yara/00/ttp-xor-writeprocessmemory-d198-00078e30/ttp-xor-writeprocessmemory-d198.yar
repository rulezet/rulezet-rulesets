rule TTP_XOR_WriteProcessMemory_d198 {
  strings:
    $key_d198 = { 86 ea [2] b4 c8 [2] b2 fd [2] 9c fd [2] a3 e1 }

  condition:
    any of them
}