rule TTP_XOR_WriteProcessMemory_d197 {
  strings:
    $key_d197 = { 86 e5 [2] b4 c7 [2] b2 f2 [2] 9c f2 [2] a3 ee }

  condition:
    any of them
}