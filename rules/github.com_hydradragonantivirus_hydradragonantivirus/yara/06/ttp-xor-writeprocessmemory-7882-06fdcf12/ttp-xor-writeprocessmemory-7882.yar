rule TTP_XOR_WriteProcessMemory_7882 {
  strings:
    $key_7882 = { 2f f0 [2] 1d d2 [2] 1b e7 [2] 35 e7 [2] 0a fb }

  condition:
    any of them
}