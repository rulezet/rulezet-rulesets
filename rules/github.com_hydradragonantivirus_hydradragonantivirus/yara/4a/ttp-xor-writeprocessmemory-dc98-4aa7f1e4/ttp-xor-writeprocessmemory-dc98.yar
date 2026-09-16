rule TTP_XOR_WriteProcessMemory_dc98 {
  strings:
    $key_dc98 = { 8b ea [2] b9 c8 [2] bf fd [2] 91 fd [2] ae e1 }

  condition:
    any of them
}