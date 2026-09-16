rule TTP_XOR_WriteProcessMemory_e5f7 {
  strings:
    $key_e5f7 = { b2 85 [2] 80 a7 [2] 86 92 [2] a8 92 [2] 97 8e }

  condition:
    any of them
}