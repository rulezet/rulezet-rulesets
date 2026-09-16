rule TTP_XOR_WriteProcessMemory_5682 {
  strings:
    $key_5682 = { 01 f0 [2] 33 d2 [2] 35 e7 [2] 1b e7 [2] 24 fb }

  condition:
    any of them
}