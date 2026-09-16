rule TTP_XOR_WriteProcessMemory_7eb3 {
  strings:
    $key_7eb3 = { 29 c1 [2] 1b e3 [2] 1d d6 [2] 33 d6 [2] 0c ca }

  condition:
    any of them
}