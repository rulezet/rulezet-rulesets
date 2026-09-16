rule TTP_XOR_WriteProcessMemory_7d17 {
  strings:
    $key_7d17 = { 2a 65 [2] 18 47 [2] 1e 72 [2] 30 72 [2] 0f 6e }

  condition:
    any of them
}