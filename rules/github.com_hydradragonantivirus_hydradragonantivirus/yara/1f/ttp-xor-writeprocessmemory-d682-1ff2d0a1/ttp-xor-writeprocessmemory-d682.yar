rule TTP_XOR_WriteProcessMemory_d682 {
  strings:
    $key_d682 = { 81 f0 [2] b3 d2 [2] b5 e7 [2] 9b e7 [2] a4 fb }

  condition:
    any of them
}