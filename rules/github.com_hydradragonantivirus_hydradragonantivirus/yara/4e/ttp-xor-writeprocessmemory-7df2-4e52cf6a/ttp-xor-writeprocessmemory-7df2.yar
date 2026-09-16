rule TTP_XOR_WriteProcessMemory_7df2 {
  strings:
    $key_7df2 = { 2a 80 [2] 18 a2 [2] 1e 97 [2] 30 97 [2] 0f 8b }

  condition:
    any of them
}