rule TTP_XOR_WriteProcessMemory_7df1 {
  strings:
    $key_7df1 = { 2a 83 [2] 18 a1 [2] 1e 94 [2] 30 94 [2] 0f 88 }

  condition:
    any of them
}