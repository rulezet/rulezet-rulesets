rule TTP_XOR_WriteProcessMemory_d694 {
  strings:
    $key_d694 = { 81 e6 [2] b3 c4 [2] b5 f1 [2] 9b f1 [2] a4 ed }

  condition:
    any of them
}