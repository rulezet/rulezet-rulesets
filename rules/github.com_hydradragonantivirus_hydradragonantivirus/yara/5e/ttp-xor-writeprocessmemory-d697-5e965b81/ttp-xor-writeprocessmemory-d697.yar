rule TTP_XOR_WriteProcessMemory_d697 {
  strings:
    $key_d697 = { 81 e5 [2] b3 c7 [2] b5 f2 [2] 9b f2 [2] a4 ee }

  condition:
    any of them
}