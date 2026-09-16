rule TTP_XOR_WriteProcessMemory_3c82 {
  strings:
    $key_3c82 = { 6b f0 [2] 59 d2 [2] 5f e7 [2] 71 e7 [2] 4e fb }

  condition:
    any of them
}