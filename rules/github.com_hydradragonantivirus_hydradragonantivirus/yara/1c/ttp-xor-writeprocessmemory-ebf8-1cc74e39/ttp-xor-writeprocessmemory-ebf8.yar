rule TTP_XOR_WriteProcessMemory_ebf8 {
  strings:
    $key_ebf8 = { bc 8a [2] 8e a8 [2] 88 9d [2] a6 9d [2] 99 81 }

  condition:
    any of them
}