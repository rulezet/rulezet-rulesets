rule TTP_XOR_WriteProcessMemory_2881 {
  strings:
    $key_2881 = { 7f f3 [2] 4d d1 [2] 4b e4 [2] 65 e4 [2] 5a f8 }

  condition:
    any of them
}