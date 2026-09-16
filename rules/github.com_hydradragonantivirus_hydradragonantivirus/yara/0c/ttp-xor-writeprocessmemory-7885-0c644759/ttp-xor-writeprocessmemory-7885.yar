rule TTP_XOR_WriteProcessMemory_7885 {
  strings:
    $key_7885 = { 2f f7 [2] 1d d5 [2] 1b e0 [2] 35 e0 [2] 0a fc }

  condition:
    any of them
}