rule TTP_XOR_WriteProcessMemory_5da7 {
  strings:
    $key_5da7 = { 0a d5 [2] 38 f7 [2] 3e c2 [2] 10 c2 [2] 2f de }

  condition:
    any of them
}