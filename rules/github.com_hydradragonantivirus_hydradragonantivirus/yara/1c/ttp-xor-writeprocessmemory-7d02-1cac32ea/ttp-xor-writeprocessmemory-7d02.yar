rule TTP_XOR_WriteProcessMemory_7d02 {
  strings:
    $key_7d02 = { 2a 70 [2] 18 52 [2] 1e 67 [2] 30 67 [2] 0f 7b }

  condition:
    any of them
}