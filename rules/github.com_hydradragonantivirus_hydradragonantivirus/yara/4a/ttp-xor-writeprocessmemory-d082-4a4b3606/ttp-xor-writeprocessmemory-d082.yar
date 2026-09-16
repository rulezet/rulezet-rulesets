rule TTP_XOR_WriteProcessMemory_d082 {
  strings:
    $key_d082 = { 87 f0 [2] b5 d2 [2] b3 e7 [2] 9d e7 [2] a2 fb }

  condition:
    any of them
}