rule TTP_XOR_WriteProcessMemory_6c82 {
  strings:
    $key_6c82 = { 3b f0 [2] 09 d2 [2] 0f e7 [2] 21 e7 [2] 1e fb }

  condition:
    any of them
}