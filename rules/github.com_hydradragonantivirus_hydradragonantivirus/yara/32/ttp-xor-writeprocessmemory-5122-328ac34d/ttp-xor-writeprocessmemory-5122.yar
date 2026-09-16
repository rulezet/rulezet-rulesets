rule TTP_XOR_WriteProcessMemory_5122 {
  strings:
    $key_5122 = { 06 50 [2] 34 72 [2] 32 47 [2] 1c 47 [2] 23 5b }

  condition:
    any of them
}