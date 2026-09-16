rule TTP_XOR_WriteProcessMemory_cbeb {
  strings:
    $key_cbeb = { 9c 99 [2] ae bb [2] a8 8e [2] 86 8e [2] b9 92 }

  condition:
    any of them
}