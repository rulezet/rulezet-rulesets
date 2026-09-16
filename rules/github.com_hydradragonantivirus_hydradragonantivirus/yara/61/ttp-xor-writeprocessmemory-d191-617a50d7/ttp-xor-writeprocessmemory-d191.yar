rule TTP_XOR_WriteProcessMemory_d191 {
  strings:
    $key_d191 = { 86 e3 [2] b4 c1 [2] b2 f4 [2] 9c f4 [2] a3 e8 }

  condition:
    any of them
}