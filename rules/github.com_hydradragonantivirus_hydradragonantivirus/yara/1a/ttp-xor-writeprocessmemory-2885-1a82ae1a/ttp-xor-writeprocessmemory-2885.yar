rule TTP_XOR_WriteProcessMemory_2885 {
  strings:
    $key_2885 = { 7f f7 [2] 4d d5 [2] 4b e0 [2] 65 e0 [2] 5a fc }

  condition:
    any of them
}