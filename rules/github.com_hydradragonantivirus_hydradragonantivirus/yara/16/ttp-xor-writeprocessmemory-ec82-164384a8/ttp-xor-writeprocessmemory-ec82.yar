rule TTP_XOR_WriteProcessMemory_ec82 {
  strings:
    $key_ec82 = { bb f0 [2] 89 d2 [2] 8f e7 [2] a1 e7 [2] 9e fb }

  condition:
    any of them
}