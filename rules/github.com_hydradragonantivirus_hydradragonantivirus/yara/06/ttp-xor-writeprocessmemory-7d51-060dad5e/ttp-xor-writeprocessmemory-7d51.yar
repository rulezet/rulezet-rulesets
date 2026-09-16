rule TTP_XOR_WriteProcessMemory_7d51 {
  strings:
    $key_7d51 = { 2a 23 [2] 18 01 [2] 1e 34 [2] 30 34 [2] 0f 28 }

  condition:
    any of them
}