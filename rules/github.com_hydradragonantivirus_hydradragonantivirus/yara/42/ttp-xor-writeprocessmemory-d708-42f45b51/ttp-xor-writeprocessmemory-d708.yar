rule TTP_XOR_WriteProcessMemory_d708 {
  strings:
    $key_d708 = { 80 7a [2] b2 58 [2] b4 6d [2] 9a 6d [2] a5 71 }

  condition:
    any of them
}