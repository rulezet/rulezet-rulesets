rule TTP_XOR_WriteProcessMemory_d196 {
  strings:
    $key_d196 = { 86 e4 [2] b4 c6 [2] b2 f3 [2] 9c f3 [2] a3 ef }

  condition:
    any of them
}