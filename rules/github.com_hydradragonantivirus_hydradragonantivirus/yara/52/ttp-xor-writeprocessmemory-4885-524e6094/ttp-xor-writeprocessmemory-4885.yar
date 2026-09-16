rule TTP_XOR_WriteProcessMemory_4885 {
  strings:
    $key_4885 = { 1f f7 [2] 2d d5 [2] 2b e0 [2] 05 e0 [2] 3a fc }

  condition:
    any of them
}