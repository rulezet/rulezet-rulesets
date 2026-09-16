rule TTP_XOR_WriteProcessMemory_18a3 {
  strings:
    $key_18a3 = { 4f d1 [2] 7d f3 [2] 7b c6 [2] 55 c6 [2] 6a da }

  condition:
    any of them
}