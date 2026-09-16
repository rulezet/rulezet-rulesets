rule TTP_XOR_WriteProcessMemory_5369 {
  strings:
    $key_5369 = { 04 1b [2] 36 39 [2] 30 0c [2] 1e 0c [2] 21 10 }

  condition:
    any of them
}