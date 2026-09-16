rule TTP_XOR_WriteProcessMemory_ebe2 {
  strings:
    $key_ebe2 = { bc 90 [2] 8e b2 [2] 88 87 [2] a6 87 [2] 99 9b }

  condition:
    any of them
}