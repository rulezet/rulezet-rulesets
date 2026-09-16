rule TTP_XOR_WriteProcessMemory_5c82 {
  strings:
    $key_5c82 = { 0b f0 [2] 39 d2 [2] 3f e7 [2] 11 e7 [2] 2e fb }

  condition:
    any of them
}