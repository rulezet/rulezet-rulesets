rule TTP_XOR_WriteProcessMemory_e5e2 {
  strings:
    $key_e5e2 = { b2 90 [2] 80 b2 [2] 86 87 [2] a8 87 [2] 97 9b }

  condition:
    any of them
}