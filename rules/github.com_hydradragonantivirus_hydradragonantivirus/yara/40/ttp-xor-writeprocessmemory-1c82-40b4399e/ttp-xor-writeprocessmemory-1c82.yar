rule TTP_XOR_WriteProcessMemory_1c82 {
  strings:
    $key_1c82 = { 4b f0 [2] 79 d2 [2] 7f e7 [2] 51 e7 [2] 6e fb }

  condition:
    any of them
}