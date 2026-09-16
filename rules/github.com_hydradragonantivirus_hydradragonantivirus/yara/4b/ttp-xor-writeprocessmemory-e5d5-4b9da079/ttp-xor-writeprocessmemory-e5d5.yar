rule TTP_XOR_WriteProcessMemory_e5d5 {
  strings:
    $key_e5d5 = { b2 a7 [2] 80 85 [2] 86 b0 [2] a8 b0 [2] 97 ac }

  condition:
    any of them
}