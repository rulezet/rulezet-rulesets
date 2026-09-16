rule TTP_XOR_WriteProcessMemory_5df0 {
  strings:
    $key_5df0 = { 0a 82 [2] 38 a0 [2] 3e 95 [2] 10 95 [2] 2f 89 }

  condition:
    any of them
}