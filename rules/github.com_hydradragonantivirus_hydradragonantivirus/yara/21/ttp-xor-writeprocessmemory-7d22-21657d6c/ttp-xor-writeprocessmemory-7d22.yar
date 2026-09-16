rule TTP_XOR_WriteProcessMemory_7d22 {
  strings:
    $key_7d22 = { 2a 50 [2] 18 72 [2] 1e 47 [2] 30 47 [2] 0f 5b }

  condition:
    any of them
}