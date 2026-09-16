rule TTP_XOR_WriteProcessMemory_d194 {
  strings:
    $key_d194 = { 86 e6 [2] b4 c4 [2] b2 f1 [2] 9c f1 [2] a3 ed }

  condition:
    any of them
}