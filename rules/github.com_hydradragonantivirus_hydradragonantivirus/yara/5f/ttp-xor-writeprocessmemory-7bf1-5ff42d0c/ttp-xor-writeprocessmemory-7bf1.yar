rule TTP_XOR_WriteProcessMemory_7bf1 {
  strings:
    $key_7bf1 = { 2c 83 [2] 1e a1 [2] 18 94 [2] 36 94 [2] 09 88 }

  condition:
    any of them
}