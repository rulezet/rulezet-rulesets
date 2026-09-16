rule TTP_XOR_WriteProcessMemory_eca2 {
  strings:
    $key_eca2 = { bb d0 [2] 89 f2 [2] 8f c7 [2] a1 c7 [2] 9e db }

  condition:
    any of them
}