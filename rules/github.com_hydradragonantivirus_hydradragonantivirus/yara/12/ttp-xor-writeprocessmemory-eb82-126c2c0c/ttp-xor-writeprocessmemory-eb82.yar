rule TTP_XOR_WriteProcessMemory_eb82 {
  strings:
    $key_eb82 = { bc f0 [2] 8e d2 [2] 88 e7 [2] a6 e7 [2] 99 fb }

  condition:
    any of them
}