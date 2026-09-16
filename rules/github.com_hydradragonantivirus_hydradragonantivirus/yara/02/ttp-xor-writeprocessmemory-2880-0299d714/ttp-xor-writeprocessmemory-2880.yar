rule TTP_XOR_WriteProcessMemory_2880 {
  strings:
    $key_2880 = { 7f f2 [2] 4d d0 [2] 4b e5 [2] 65 e5 [2] 5a f9 }

  condition:
    any of them
}