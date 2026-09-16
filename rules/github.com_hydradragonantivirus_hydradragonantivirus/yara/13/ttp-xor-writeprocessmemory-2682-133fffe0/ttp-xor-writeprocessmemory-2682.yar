rule TTP_XOR_WriteProcessMemory_2682 {
  strings:
    $key_2682 = { 71 f0 [2] 43 d2 [2] 45 e7 [2] 6b e7 [2] 54 fb }

  condition:
    any of them
}