rule TTP_XOR_WriteProcessMemory_d698 {
  strings:
    $key_d698 = { 81 ea [2] b3 c8 [2] b5 fd [2] 9b fd [2] a4 e1 }

  condition:
    any of them
}