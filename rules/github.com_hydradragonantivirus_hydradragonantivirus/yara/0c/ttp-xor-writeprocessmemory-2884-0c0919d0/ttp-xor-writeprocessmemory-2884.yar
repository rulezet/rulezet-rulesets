rule TTP_XOR_WriteProcessMemory_2884 {
  strings:
    $key_2884 = { 7f f6 [2] 4d d4 [2] 4b e1 [2] 65 e1 [2] 5a fd }

  condition:
    any of them
}