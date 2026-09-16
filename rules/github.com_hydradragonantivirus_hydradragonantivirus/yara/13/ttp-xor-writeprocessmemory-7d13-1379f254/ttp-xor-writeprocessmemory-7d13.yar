rule TTP_XOR_WriteProcessMemory_7d13 {
  strings:
    $key_7d13 = { 2a 61 [2] 18 43 [2] 1e 76 [2] 30 76 [2] 0f 6a }

  condition:
    any of them
}