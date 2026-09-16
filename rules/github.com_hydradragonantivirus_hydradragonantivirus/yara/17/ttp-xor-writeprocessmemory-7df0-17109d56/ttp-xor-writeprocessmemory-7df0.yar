rule TTP_XOR_WriteProcessMemory_7df0 {
  strings:
    $key_7df0 = { 2a 82 [2] 18 a0 [2] 1e 95 [2] 30 95 [2] 0f 89 }

  condition:
    any of them
}