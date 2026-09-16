rule TTP_XOR_WriteProcessMemory_ecec {
  strings:
    $key_ecec = { bb 9e [2] 89 bc [2] 8f 89 [2] a1 89 [2] 9e 95 }

  condition:
    any of them
}