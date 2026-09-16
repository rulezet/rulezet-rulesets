rule TTP_XOR_WriteProcessMemory_7df3 {
  strings:
    $key_7df3 = { 2a 81 [2] 18 a3 [2] 1e 96 [2] 30 96 [2] 0f 8a }

  condition:
    any of them
}