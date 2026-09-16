rule TTP_XOR_WriteProcessMemory_7da7 {
  strings:
    $key_7da7 = { 2a d5 [2] 18 f7 [2] 1e c2 [2] 30 c2 [2] 0f de }

  condition:
    any of them
}