rule TTP_XOR_WriteProcessMemory_c4d7 {
  strings:
    $key_c4d7 = { 93 a5 [2] a1 87 [2] a7 b2 [2] 89 b2 [2] b6 ae }

  condition:
    any of them
}