rule TTP_XOR_WriteProcessMemory_199c {
  strings:
    $key_199c = { 4e ee [2] 7c cc [2] 7a f9 [2] 54 f9 [2] 6b e5 }

  condition:
    any of them
}