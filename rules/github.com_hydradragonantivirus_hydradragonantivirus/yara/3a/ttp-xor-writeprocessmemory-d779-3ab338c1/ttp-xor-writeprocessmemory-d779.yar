rule TTP_XOR_WriteProcessMemory_d779 {
  strings:
    $key_d779 = { 80 0b [2] b2 29 [2] b4 1c [2] 9a 1c [2] a5 00 }

  condition:
    any of them
}