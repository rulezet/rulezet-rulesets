rule TTP_XOR_WriteProcessMemory_d171 {
  strings:
    $key_d171 = { 86 03 [2] b4 21 [2] b2 14 [2] 9c 14 [2] a3 08 }

  condition:
    any of them
}