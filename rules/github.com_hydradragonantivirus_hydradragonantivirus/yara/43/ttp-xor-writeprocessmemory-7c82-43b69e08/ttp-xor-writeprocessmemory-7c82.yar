rule TTP_XOR_WriteProcessMemory_7c82 {
  strings:
    $key_7c82 = { 2b f0 [2] 19 d2 [2] 1f e7 [2] 31 e7 [2] 0e fb }

  condition:
    any of them
}