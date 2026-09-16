rule TTP_XOR_WriteProcessMemory_c594 {
  strings:
    $key_c594 = { 92 e6 [2] a0 c4 [2] a6 f1 [2] 88 f1 [2] b7 ed }

  condition:
    any of them
}