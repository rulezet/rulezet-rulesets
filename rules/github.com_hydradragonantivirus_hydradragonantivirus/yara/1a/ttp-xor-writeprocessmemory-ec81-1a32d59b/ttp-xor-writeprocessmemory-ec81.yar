rule TTP_XOR_WriteProcessMemory_ec81 {
  strings:
    $key_ec81 = { bb f3 [2] 89 d1 [2] 8f e4 [2] a1 e4 [2] 9e f8 }

  condition:
    any of them
}