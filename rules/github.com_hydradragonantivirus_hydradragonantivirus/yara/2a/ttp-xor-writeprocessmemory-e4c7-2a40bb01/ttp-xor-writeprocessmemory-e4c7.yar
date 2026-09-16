rule TTP_XOR_WriteProcessMemory_e4c7 {
  strings:
    $key_e4c7 = { b3 b5 [2] 81 97 [2] 87 a2 [2] a9 a2 [2] 96 be }

  condition:
    any of them
}