rule TTP_XOR_WriteProcessMemory_e4b3 {
  strings:
    $key_e4b3 = { b3 c1 [2] 81 e3 [2] 87 d6 [2] a9 d6 [2] 96 ca }

  condition:
    any of them
}