rule TTP_XOR_WriteProcessMemory_d4b3 {
  strings:
    $key_d4b3 = { 83 c1 [2] b1 e3 [2] b7 d6 [2] 99 d6 [2] a6 ca }

  condition:
    any of them
}