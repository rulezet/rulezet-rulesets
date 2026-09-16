rule TTP_XOR_WriteProcessMemory_d691 {
  strings:
    $key_d691 = { 81 e3 [2] b3 c1 [2] b5 f4 [2] 9b f4 [2] a4 e8 }

  condition:
    any of them
}