rule TTP_XOR_WriteProcessMemory_ebe0 {
  strings:
    $key_ebe0 = { bc 92 [2] 8e b0 [2] 88 85 [2] a6 85 [2] 99 99 }

  condition:
    any of them
}