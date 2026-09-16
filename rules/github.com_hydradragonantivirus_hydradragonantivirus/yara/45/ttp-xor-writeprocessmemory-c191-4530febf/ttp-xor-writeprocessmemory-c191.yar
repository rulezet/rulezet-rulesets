rule TTP_XOR_WriteProcessMemory_c191 {
  strings:
    $key_c191 = { 96 e3 [2] a4 c1 [2] a2 f4 [2] 8c f4 [2] b3 e8 }

  condition:
    any of them
}