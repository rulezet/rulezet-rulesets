rule TTP_XOR_WriteProcessMemory_d142 {
  strings:
    $key_d142 = { 86 30 [2] b4 12 [2] b2 27 [2] 9c 27 [2] a3 3b }

  condition:
    any of them
}