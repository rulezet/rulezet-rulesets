rule TTP_XOR_WriteProcessMemory_099c {
  strings:
    $key_099c = { 5e ee [2] 6c cc [2] 6a f9 [2] 44 f9 [2] 7b e5 }

  condition:
    any of them
}