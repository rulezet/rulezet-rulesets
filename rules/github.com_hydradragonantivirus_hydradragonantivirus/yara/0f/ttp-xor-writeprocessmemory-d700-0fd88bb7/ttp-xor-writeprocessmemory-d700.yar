rule TTP_XOR_WriteProcessMemory_d700 {
  strings:
    $key_d700 = { 80 72 [2] b2 50 [2] b4 65 [2] 9a 65 [2] a5 79 }

  condition:
    any of them
}