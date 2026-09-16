rule TTP_XOR_WriteProcessMemory_e573 {
  strings:
    $key_e573 = { b2 01 [2] 80 23 [2] 86 16 [2] a8 16 [2] 97 0a }

  condition:
    any of them
}