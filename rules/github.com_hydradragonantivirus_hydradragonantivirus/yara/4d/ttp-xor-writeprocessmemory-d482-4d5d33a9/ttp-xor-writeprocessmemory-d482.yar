rule TTP_XOR_WriteProcessMemory_d482 {
  strings:
    $key_d482 = { 83 f0 [2] b1 d2 [2] b7 e7 [2] 99 e7 [2] a6 fb }

  condition:
    any of them
}