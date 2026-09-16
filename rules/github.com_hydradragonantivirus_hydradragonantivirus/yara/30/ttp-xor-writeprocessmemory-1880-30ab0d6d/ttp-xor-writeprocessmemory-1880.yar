rule TTP_XOR_WriteProcessMemory_1880 {
  strings:
    $key_1880 = { 4f f2 [2] 7d d0 [2] 7b e5 [2] 55 e5 [2] 6a f9 }

  condition:
    any of them
}