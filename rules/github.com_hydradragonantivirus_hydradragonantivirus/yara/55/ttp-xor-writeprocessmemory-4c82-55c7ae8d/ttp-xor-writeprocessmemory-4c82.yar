rule TTP_XOR_WriteProcessMemory_4c82 {
  strings:
    $key_4c82 = { 1b f0 [2] 29 d2 [2] 2f e7 [2] 01 e7 [2] 3e fb }

  condition:
    any of them
}