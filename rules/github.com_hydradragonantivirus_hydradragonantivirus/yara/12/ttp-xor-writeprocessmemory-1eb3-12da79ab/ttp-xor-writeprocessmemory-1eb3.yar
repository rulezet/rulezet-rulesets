rule TTP_XOR_WriteProcessMemory_1eb3 {
  strings:
    $key_1eb3 = { 49 c1 [2] 7b e3 [2] 7d d6 [2] 53 d6 [2] 6c ca }

  condition:
    any of them
}