rule TTP_XOR_WriteProcessMemory_1884 {
  strings:
    $key_1884 = { 4f f6 [2] 7d d4 [2] 7b e1 [2] 55 e1 [2] 6a fd }

  condition:
    any of them
}