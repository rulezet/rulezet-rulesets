rule TTP_XOR_WriteProcessMemory_d163 {
  strings:
    $key_d163 = { 86 11 [2] b4 33 [2] b2 06 [2] 9c 06 [2] a3 1a }

  condition:
    any of them
}