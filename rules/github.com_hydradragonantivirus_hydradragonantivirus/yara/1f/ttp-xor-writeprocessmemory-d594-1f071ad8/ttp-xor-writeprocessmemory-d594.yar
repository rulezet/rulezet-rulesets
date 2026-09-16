rule TTP_XOR_WriteProcessMemory_d594 {
  strings:
    $key_d594 = { 82 e6 [2] b0 c4 [2] b6 f1 [2] 98 f1 [2] a7 ed }

  condition:
    any of them
}