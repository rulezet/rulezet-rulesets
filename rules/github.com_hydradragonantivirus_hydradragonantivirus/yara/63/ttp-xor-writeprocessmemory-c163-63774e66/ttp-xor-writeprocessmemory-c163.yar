rule TTP_XOR_WriteProcessMemory_c163 {
  strings:
    $key_c163 = { 96 11 [2] a4 33 [2] a2 06 [2] 8c 06 [2] b3 1a }

  condition:
    any of them
}