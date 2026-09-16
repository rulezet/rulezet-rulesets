rule TTP_XOR_WriteProcessMemory_ece2 {
  strings:
    $key_ece2 = { bb 90 [2] 89 b2 [2] 8f 87 [2] a1 87 [2] 9e 9b }

  condition:
    any of them
}