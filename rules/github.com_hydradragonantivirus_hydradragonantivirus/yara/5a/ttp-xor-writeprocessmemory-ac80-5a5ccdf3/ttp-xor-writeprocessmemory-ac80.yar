rule TTP_XOR_WriteProcessMemory_ac80 {
  strings:
    $key_ac80 = { fb f2 [2] c9 d0 [2] cf e5 [2] e1 e5 [2] de f9 }

  condition:
    any of them
}