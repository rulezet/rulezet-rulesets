rule TTP_XOR_WriteProcessMemory_ebf9 {
  strings:
    $key_ebf9 = { bc 8b [2] 8e a9 [2] 88 9c [2] a6 9c [2] 99 80 }

  condition:
    any of them
}