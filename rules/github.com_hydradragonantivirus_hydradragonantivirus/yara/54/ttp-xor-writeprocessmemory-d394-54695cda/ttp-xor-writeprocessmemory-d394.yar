rule TTP_XOR_WriteProcessMemory_d394 {
  strings:
    $key_d394 = { 84 e6 [2] b6 c4 [2] b0 f1 [2] 9e f1 [2] a1 ed }

  condition:
    any of them
}