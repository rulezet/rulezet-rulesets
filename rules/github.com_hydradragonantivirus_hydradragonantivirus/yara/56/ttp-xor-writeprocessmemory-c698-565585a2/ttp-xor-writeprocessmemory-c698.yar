rule TTP_XOR_WriteProcessMemory_c698 {
  strings:
    $key_c698 = { 91 ea [2] a3 c8 [2] a5 fd [2] 8b fd [2] b4 e1 }

  condition:
    any of them
}