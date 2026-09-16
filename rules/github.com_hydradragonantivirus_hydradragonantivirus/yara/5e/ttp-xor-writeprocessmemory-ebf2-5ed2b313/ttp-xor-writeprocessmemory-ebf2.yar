rule TTP_XOR_WriteProcessMemory_ebf2 {
  strings:
    $key_ebf2 = { bc 80 [2] 8e a2 [2] 88 97 [2] a6 97 [2] 99 8b }

  condition:
    any of them
}