rule TTP_XOR_WriteProcessMemory_699c {
  strings:
    $key_699c = { 3e ee [2] 0c cc [2] 0a f9 [2] 24 f9 [2] 1b e5 }

  condition:
    any of them
}