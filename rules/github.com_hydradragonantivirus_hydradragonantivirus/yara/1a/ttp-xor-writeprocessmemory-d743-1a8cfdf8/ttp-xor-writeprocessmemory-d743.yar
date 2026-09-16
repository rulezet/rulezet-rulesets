rule TTP_XOR_WriteProcessMemory_d743 {
  strings:
    $key_d743 = { 80 31 [2] b2 13 [2] b4 26 [2] 9a 26 [2] a5 3a }

  condition:
    any of them
}