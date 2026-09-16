rule TTP_XOR_WriteProcessMemory_c394 {
  strings:
    $key_c394 = { 94 e6 [2] a6 c4 [2] a0 f1 [2] 8e f1 [2] b1 ed }

  condition:
    any of them
}