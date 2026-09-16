rule TTP_XOR_WriteProcessMemory_3885 {
  strings:
    $key_3885 = { 6f f7 [2] 5d d5 [2] 5b e0 [2] 75 e0 [2] 4a fc }

  condition:
    any of them
}