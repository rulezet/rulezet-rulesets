rule TTP_XOR_WriteProcessMemory_eca4 {
  strings:
    $key_eca4 = { bb d6 [2] 89 f4 [2] 8f c1 [2] a1 c1 [2] 9e dd }

  condition:
    any of them
}