rule TTP_XOR_WriteProcessMemory_d185 {
  strings:
    $key_d185 = { 86 f7 [2] b4 d5 [2] b2 e0 [2] 9c e0 [2] a3 fc }

  condition:
    any of them
}