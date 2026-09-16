rule TTP_XOR_WriteProcessMemory_6885 {
  strings:
    $key_6885 = { 3f f7 [2] 0d d5 [2] 0b e0 [2] 25 e0 [2] 1a fc }

  condition:
    any of them
}