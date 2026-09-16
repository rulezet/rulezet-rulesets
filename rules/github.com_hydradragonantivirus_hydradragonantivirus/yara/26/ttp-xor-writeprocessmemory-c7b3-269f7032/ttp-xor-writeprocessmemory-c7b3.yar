rule TTP_XOR_WriteProcessMemory_c7b3 {
  strings:
    $key_c7b3 = { 90 c1 [2] a2 e3 [2] a4 d6 [2] 8a d6 [2] b5 ca }

  condition:
    any of them
}