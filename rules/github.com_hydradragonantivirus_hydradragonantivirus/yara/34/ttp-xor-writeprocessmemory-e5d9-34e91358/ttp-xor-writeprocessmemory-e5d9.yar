rule TTP_XOR_WriteProcessMemory_e5d9 {
  strings:
    $key_e5d9 = { b2 ab [2] 80 89 [2] 86 bc [2] a8 bc [2] 97 a0 }

  condition:
    any of them
}