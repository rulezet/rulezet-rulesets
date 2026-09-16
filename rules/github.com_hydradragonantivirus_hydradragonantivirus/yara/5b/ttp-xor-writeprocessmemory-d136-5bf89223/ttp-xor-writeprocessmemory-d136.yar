rule TTP_XOR_WriteProcessMemory_d136 {
  strings:
    $key_d136 = { 86 44 [2] b4 66 [2] b2 53 [2] 9c 53 [2] a3 4f }

  condition:
    any of them
}