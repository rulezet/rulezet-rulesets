rule TTP_XOR_WriteProcessMemory_2eb3 {
  strings:
    $key_2eb3 = { 79 c1 [2] 4b e3 [2] 4d d6 [2] 63 d6 [2] 5c ca }

  condition:
    any of them
}