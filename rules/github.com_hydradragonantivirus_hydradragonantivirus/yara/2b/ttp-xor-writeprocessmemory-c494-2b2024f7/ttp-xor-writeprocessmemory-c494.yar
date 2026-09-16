rule TTP_XOR_WriteProcessMemory_c494 {
  strings:
    $key_c494 = { 93 e6 [2] a1 c4 [2] a7 f1 [2] 89 f1 [2] b6 ed }

  condition:
    any of them
}