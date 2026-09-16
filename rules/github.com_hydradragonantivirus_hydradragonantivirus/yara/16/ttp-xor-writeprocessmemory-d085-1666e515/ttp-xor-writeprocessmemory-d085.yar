rule TTP_XOR_WriteProcessMemory_d085 {
  strings:
    $key_d085 = { 87 f7 [2] b5 d5 [2] b3 e0 [2] 9d e0 [2] a2 fc }

  condition:
    any of them
}