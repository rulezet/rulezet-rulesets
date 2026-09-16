rule TTP_XOR_WriteProcessMemory_d7d7 {
  strings:
    $key_d7d7 = { 80 a5 [2] b2 87 [2] b4 b2 [2] 9a b2 [2] a5 ae }

  condition:
    any of them
}