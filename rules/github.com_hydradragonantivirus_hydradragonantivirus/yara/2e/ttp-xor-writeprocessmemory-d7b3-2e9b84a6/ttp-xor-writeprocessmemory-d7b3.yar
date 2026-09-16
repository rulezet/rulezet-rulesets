rule TTP_XOR_WriteProcessMemory_d7b3 {
  strings:
    $key_d7b3 = { 80 c1 [2] b2 e3 [2] b4 d6 [2] 9a d6 [2] a5 ca }

  condition:
    any of them
}