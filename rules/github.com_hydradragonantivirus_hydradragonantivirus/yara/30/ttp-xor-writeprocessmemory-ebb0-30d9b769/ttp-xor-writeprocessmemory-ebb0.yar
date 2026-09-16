rule TTP_XOR_WriteProcessMemory_ebb0 {
  strings:
    $key_ebb0 = { bc c2 [2] 8e e0 [2] 88 d5 [2] a6 d5 [2] 99 c9 }

  condition:
    any of them
}