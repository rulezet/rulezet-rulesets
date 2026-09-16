rule TTP_XOR_WriteProcessMemory_1885 {
  strings:
    $key_1885 = { 4f f7 [2] 7d d5 [2] 7b e0 [2] 55 e0 [2] 6a fc }

  condition:
    any of them
}