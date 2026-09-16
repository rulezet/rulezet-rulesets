rule TTP_XOR_WriteProcessMemory_ebf3 {
  strings:
    $key_ebf3 = { bc 81 [2] 8e a3 [2] 88 96 [2] a6 96 [2] 99 8a }

  condition:
    any of them
}