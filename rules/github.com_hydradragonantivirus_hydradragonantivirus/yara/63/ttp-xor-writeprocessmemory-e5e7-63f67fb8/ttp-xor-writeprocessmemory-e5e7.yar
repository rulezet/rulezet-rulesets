rule TTP_XOR_WriteProcessMemory_e5e7 {
  strings:
    $key_e5e7 = { b2 95 [2] 80 b7 [2] 86 82 [2] a8 82 [2] 97 9e }

  condition:
    any of them
}