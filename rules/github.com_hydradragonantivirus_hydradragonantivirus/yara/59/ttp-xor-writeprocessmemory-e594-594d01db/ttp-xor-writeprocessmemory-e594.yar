rule TTP_XOR_WriteProcessMemory_e594 {
  strings:
    $key_e594 = { b2 e6 [2] 80 c4 [2] 86 f1 [2] a8 f1 [2] 97 ed }

  condition:
    any of them
}