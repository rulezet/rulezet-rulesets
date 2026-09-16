rule TTP_XOR_WriteProcessMemory_d485 {
  strings:
    $key_d485 = { 83 f7 [2] b1 d5 [2] b7 e0 [2] 99 e0 [2] a6 fc }

  condition:
    any of them
}