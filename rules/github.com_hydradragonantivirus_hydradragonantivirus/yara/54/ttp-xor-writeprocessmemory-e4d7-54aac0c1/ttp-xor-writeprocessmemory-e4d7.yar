rule TTP_XOR_WriteProcessMemory_e4d7 {
  strings:
    $key_e4d7 = { b3 a5 [2] 81 87 [2] 87 b2 [2] a9 b2 [2] 96 ae }

  condition:
    any of them
}